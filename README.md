Stealth Packet Capture Tool
A Python-based network packet capture utility designed with stealth and minimal detection in mind. This tool provides basic packet sniffing capabilities while implementing various techniques to reduce its footprint and avoid detection.

Features
Network Interface Discovery: List all available network interfaces for capture

BPF Filter Support: Apply standard Berkeley Packet Filter expressions to focus captures

PCAP Output: Save captured packets to PCAP files for later analysis

Stealth Techniques:

Process name randomization

String obfuscation in memory

Anti-debugging detection

Clean exit handlers

Minimal memory footprint during operation

Requirements
Python 3.6+

Scapy library (pip install scapy)

Root/Administrator privileges (for packet capture)

Linux: libpcap development libraries

Windows: Npcap or WinPcap (recommend Npcap in promiscuous mode)

Installation
Clone the repository:

bash
git clone https://github.com/VastScientist69/Packet-Sniffer.git
cd stealth-packet-capture
Install required dependencies:

bash
pip install scapy
On Linux, install libpcap headers:

bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/CentOS
sudo yum install libpcap-devel
Usage
Listing Available Interfaces
bash
sudo python3 stealth_capture.py
Basic Packet Capture
bash
sudo python3 stealth_capture.py 0
Capture with BPF Filter
bash
sudo python3 stealth_capture.py 0 "tcp port 80"
Capture and Save to PCAP
bash
sudo python3 stealth_capture.py 0 "" output.pcap
Combined Filter and Save
bash
sudo python3 stealth_capture.py 0 "tcp port 443" https.pcap
Command Line Arguments
Argument	Description	Required
device_index	Index of the network interface to use	Yes
bpf_filter	BPF filter expression (empty string for none)	No
output_file	Path to save captured packets (PCAP format)	No
Output Format
The tool displays captured packets in the following format:

text
HH:MM:SS.ms PROTOCOL  SOURCE -> DESTINATION len=LENGTH
Example:

text
14:23:45.123 TCP:443  192.168.1.100 -> 172.217.16.206 len=542
14:23:45.126 TCP:443  172.217.16.206 -> 192.168.1.100 len=1380
Stealth Features Explained
Process Name Randomization
The tool attempts to change its process name to a random 8-character string to appear less suspicious in process listings.

String Obfuscation
Sensitive strings are XOR-obfuscated in memory to make memory analysis more difficult.

Anti-Debugging Protection
Basic checks for debugging/tracing activity with automatic termination if detected.

Clean Exit Handlers
Proper signal handling for SIGINT and SIGTERM to ensure clean exits without artifacts.

Legal and Ethical Considerations
⚠️ IMPORTANT: This tool is intended for:

Educational purposes

Security research

Authorized penetration testing

Network troubleshooting

Always obtain proper authorization before monitoring any network traffic. Unauthorized packet capture may violate:

Computer Fraud and Abuse Act (CFAA)

Wiretap laws

Organizational policies

Local and international regulations

The developers assume no liability for misuse of this tool.

Limitations
Requires elevated privileges

May not work on all network interfaces (especially virtualized environments)

Limited protocol decoding compared to full-featured analyzers like Wireshark

Stealth features are basic and may not evade advanced detection systems

Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for:

Bug fixes

Additional features

Improved stealth techniques

Documentation improvements

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
The Scapy project for the excellent packet manipulation library

Npcap/WinPcap for Windows packet capture capabilities

libpcap for Unix-like system packet capture

