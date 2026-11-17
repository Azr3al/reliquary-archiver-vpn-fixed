Original Repo: https://github.com/IceDynamix/reliquary-archiver




Live captures didn't work for anyone playing through a VPN like Proton VPN, WireGuard or OpenVPN.

Npcap exposes these tunnel adapters with a raw IP link type (DLT_RAW, which is 12 on Windows) instead of Ethernet. Live captures passed packets straight to the sniffer, which expects Ethernet frames, so everything from the tunnel was silently dropped and the archiver stayed on "Waiting for login" forever. Offline .pcap files already got their packets converted to Ethernet frames, live captures didn't.

Changes (all in src/capture/pcap.rs):
- Live captures now run packets through the same conversion as files, based on the device's link type
- The conversion also handles NULL/LOOP (4-byte address family header) and checks the common link types by number, so live captures don't look up names per packet
- Devices with an Unknown connection status are no longer skipped, since some tunnel adapters report that
- Logs each device's link type when capture starts, which helps with debugging
- Added tests for RAW (12), NULL and LOOP

Tested on Windows 10 with Npcap 1.90 and Proton VPN (WireGuard): the tunnel adapter shows up as RAW, the archiver connects, and the login, inventory and character data are processed.

Note: VPNs that grab traffic with their own driver before it reaches any network adapter (X-VPN, for example) still can't be captured, since the traffic never shows up on any adapter.
