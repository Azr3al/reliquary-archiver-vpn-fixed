use std::future;
use std::path::PathBuf;

use ::pcap::{self, Capture, Device as PcapDevice};
use futures::StreamExt;
use pcap::PacketCodec;
use tracing::{info, instrument, warn};

use super::*;

pub struct PcapBackend;

impl DeviceBackend for PcapBackend {
    type Device = PcapDevice;

    fn list_devices(&self) -> Result<Vec<Self::Device>> {
        Ok(PcapDevice::list()
            .map_err(|e| CaptureError::Device(Box::new(e)))?
            .into_iter()
            // VPN tunnel adapters often can't tell whether they're connected and report Unknown
            .filter(|d| {
                matches!(
                    d.flags.connection_status,
                    pcap::ConnectionStatus::Connected | pcap::ConnectionStatus::Unknown
                )
            })
            .filter(|d| !d.addresses.is_empty())
            .filter(|d| !d.flags.is_loopback())
            .collect::<Vec<_>>())
    }

    fn device_name(device: &Self::Device) -> String {
        device.name.clone()
    }

    #[instrument(skip_all, fields(device = device.desc))]
    fn open_device(device: &Self::Device) -> Result<PacketStream> {
        let capture = Capture::from_device(device.clone())
            .map_err(|e| CaptureError::Device(Box::new(e)))?
            .immediate_mode(true)
            .promisc(true)
            .timeout(1000)
            .buffer_size(1024 * 1024 * 16) // 16MB
            .open()
            .map_err(|e| CaptureError::Capture(Box::new(e)))?;

        let mut capture = capture.setnonblock().map_err(|e| CaptureError::Capture(Box::new(e)))?;

        capture
            .filter(&pcap_filter(), true)
            .map_err(|e| CaptureError::Filter(Box::new(e)))?;

        let source_id = source_id(&device.name);

        // VPN tunnels (WireGuard, OpenVPN TUN, ExpressVPN Lightway, ...) hand over bare IP packets
        // instead of Ethernet frames, so the frames have to be normalized like for files
        let linktype = capture.get_datalink();
        info!(linktype = ?linktype.get_name().ok(), "Capturing on device");

        let device_name = device.name.clone();
        let stream = capture
            .stream(Codec { source_id, linktype })
            .map_err(|e| CaptureError::Capture(Box::new(e)))?;

        // A capture that fails once keeps failing: on Windows the stream retries straight away, so
        // one error turns into thousands a second. End the stream on the first error instead.
        // DeviceSource then drops this device, and opens it again if it's still listed on its
        // next check for new devices.
        Ok(stream
            .take_while(move |r| {
                future::ready(match r {
                    Ok(_) => true,
                    Err(pcap::Error::InterfaceDisappeared) => {
                        info!(%device_name, "Device went away, stopping its capture");
                        false
                    }
                    Err(e) => {
                        warn!(%e, %device_name, "Capture failed, stopping it until the device is picked up again");
                        false
                    }
                })
            })
            .filter_map(|r| future::ready(r.ok().flatten().map(Ok)))
            .boxed())
    }
}

pub struct Codec {
    source_id: u64,
    linktype: pcap::Linktype,
}

impl PacketCodec for Codec {
    /// `None` for packets that can't be turned into an Ethernet frame
    type Item = Option<Packet>;

    fn decode(&mut self, pkt: pcap::Packet) -> Self::Item {
        let data = normalize_payload(self.linktype, pkt.data).ok()?;
        Some(Packet {
            source_id: self.source_id,
            data,
        })
    }
}

/// Reads packets from a recorded .pcap file
pub struct PcapFileSource {
    path: PathBuf,
}

impl PcapFileSource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl PacketSource for PcapFileSource {
    #[instrument(skip_all)]
    fn open(self: Box<Self>) -> Result<PacketStream> {
        info!("Capturing from pcap file: {}", self.path.display());
        let mut capture = Capture::from_file(&self.path).map_err(|e| CaptureError::Device(Box::new(e)))?;
        let linktype = capture.get_datalink();
        capture
            .filter(&pcap_filter(), false)
            .map_err(|e| CaptureError::Filter(Box::new(e)))?;

        let source_id = source_id(&self.path);

        Ok(blocking_stream(move |send| {
            while let Ok(packet) = capture.next_packet() {
                let Ok(data) = normalize_payload(linktype, packet.data) else {
                    continue;
                };

                if !send(Packet { source_id, data }) {
                    break;
                }
            }
        }))
    }
}

/// Only lets the game's traffic through
fn pcap_filter() -> String {
    format!("udp portrange {}-{}", GAME_PORTS.0, GAME_PORTS.1)
}

/// Turns a captured packet (live or from a file) into an Ethernet frame, which is what the sniffer
/// expects. Physical adapters already deliver Ethernet frames, VPN tunnel adapters deliver bare IP
/// packets (RAW) or IP packets behind a 4 byte address family header (NULL/LOOP).
fn normalize_payload(linktype: pcap::Linktype, payload: &[u8]) -> std::result::Result<Vec<u8>, String> {
    fn frame_ip_payload(payload: &[u8], ethertype: u16) -> Vec<u8> {
        // Use a synthetic Ethernet header so the downstream sniffer can parse RAW/IP captures.
        let mut framed = Vec::with_capacity(14 + payload.len());
        framed.extend_from_slice(&[0u8; 12]);
        framed.extend_from_slice(&ethertype.to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }

    fn frame_raw_ip(payload: &[u8]) -> std::result::Result<Vec<u8>, String> {
        let Some(first) = payload.first() else {
            return Err("packet payload is empty".to_string());
        };
        let version = first >> 4;
        match version {
            4 => Ok(frame_ip_payload(payload, 0x0800)),
            6 => Ok(frame_ip_payload(payload, 0x86DD)),
            _ => Err(format!("RAW packet does not start with IPv4/IPv6 header (version={version})")),
        }
    }

    // The common cases, checked by number first so live captures don't look up names per packet
    match linktype {
        pcap::Linktype::ETHERNET => return Ok(payload.to_vec()),
        // Npcap reports VPN tunnels (WireGuard, OpenVPN DCO, ...) as DLT_RAW, which is 12 on Windows
        pcap::Linktype::RAW | pcap::Linktype(12) => return frame_raw_ip(payload),
        // The address family header's value differs between platforms, the IP version doesn't
        pcap::Linktype::NULL | pcap::Linktype::LOOP => {
            return match payload.get(4..) {
                Some(ip) if !ip.is_empty() => frame_raw_ip(ip),
                _ => Err("NULL/LOOP packet is too short".to_string()),
            };
        }
        _ => {}
    }

    let link_name = linktype.get_name().ok();
    let is_ethernet = linktype == pcap::Linktype::ETHERNET || link_name.as_deref() == Some("EN10MB");
    let is_ipv4 = linktype == pcap::Linktype::IPV4 || link_name.as_deref() == Some("IPV4");
    let is_ipv6 = linktype == pcap::Linktype::IPV6 || link_name.as_deref() == Some("IPV6");
    let is_raw_ip = linktype == pcap::Linktype::RAW || linktype.0 == 12 || link_name.as_deref() == Some("RAW");

    if is_ethernet {
        return Ok(payload.to_vec());
    }

    if payload.is_empty() {
        return Err("packet payload is empty".to_string());
    }

    if is_ipv4 {
        return Ok(frame_ip_payload(payload, 0x0800));
    }

    if is_ipv6 {
        return Ok(frame_ip_payload(payload, 0x86DD));
    }

    if is_raw_ip {
        return frame_raw_ip(payload);
    }

    let link_name = link_name.unwrap_or_else(|| "UNKNOWN".to_string());
    Err(format!("unsupported pcap datalink {link_name} ({})", linktype.0))
}

#[cfg(test)]
mod tests {
    use ::pcap::Linktype;

    use super::normalize_payload;

    #[test]
    fn ethernet_frames_are_passed_through() {
        let frame = vec![1, 2, 3, 4];
        assert_eq!(normalize_payload(Linktype::ETHERNET, &frame).unwrap(), frame);
    }

    #[test]
    fn raw_ip_packets_get_a_synthetic_ethernet_header() {
        let ipv4 = [0x45, 0, 0, 20];
        let framed = normalize_payload(Linktype::RAW, &ipv4).unwrap();
        assert_eq!(framed.len(), 14 + ipv4.len());
        assert_eq!(&framed[12..14], &[0x08, 0x00]);
        assert_eq!(&framed[14..], &ipv4);

        // What Npcap reports for a Proton VPN / WireGuard adapter
        let framed = normalize_payload(Linktype(12), &ipv4).unwrap();
        assert_eq!(&framed[12..14], &[0x08, 0x00]);
        assert_eq!(&framed[14..], &ipv4);

        let ipv6 = [0x60, 0, 0, 0];
        let framed = normalize_payload(Linktype::RAW, &ipv6).unwrap();
        assert_eq!(&framed[12..14], &[0x86, 0xDD]);
    }

    #[test]
    fn unusable_packets_are_rejected() {
        assert!(normalize_payload(Linktype::RAW, &[]).is_err());
        assert!(normalize_payload(Linktype::RAW, &[0x10]).is_err());
        assert!(normalize_payload(Linktype::NULL, &[0x45]).is_err());
        assert!(normalize_payload(Linktype::NULL, &[2, 0, 0, 0]).is_err());
        assert!(normalize_payload(Linktype::PPP, &[0x45]).is_err());
    }

    #[test]
    fn vpn_null_and_loop_packets_lose_the_family_header() {
        // Windows/little-endian AF_INET (2) as DLT_NULL, then an IPv4 header start
        let null_v4 = [2, 0, 0, 0, 0x45, 0, 0, 20];
        let framed = normalize_payload(Linktype::NULL, &null_v4).unwrap();
        assert_eq!(&framed[12..14], &[0x08, 0x00]);
        assert_eq!(&framed[14..], &null_v4[4..]);

        // Big-endian AF_INET6 as DLT_LOOP
        let loop_v6 = [0, 0, 0, 24, 0x60, 0, 0, 0];
        let framed = normalize_payload(Linktype::LOOP, &loop_v6).unwrap();
        assert_eq!(&framed[12..14], &[0x86, 0xDD]);
        assert_eq!(&framed[14..], &loop_v6[4..]);
    }
}
