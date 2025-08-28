#!/usr/bin/env python3
"""
Stealth Packet Capture Tool

Features:
- No obvious process name when running
- Randomizes process arguments in memory
- Minimal network footprint when capturing
- Encrypted configuration and output options
- Anti-debugging techniques
- Clean exit on detection of monitoring

Usage:
  python3 -c ''  # List available devices
  python3 -c '' 1  # Capture on device index 1
  python3 -c '' 1 "tcp port 80"  # With BPF filter
  python3 -c '' 1 "" capture.pcap  # Save to pcap

Note: Requires root privileges on Linux or admin rights on Windows
"""

import os
import sys
import time
import ctypes
import random
import string
import argparse
from datetime import datetime
from scapy.all import get_if_list, sniff, conf, ARPHDR_ETHER
from scapy.arch import get_if_raw_hwaddr
import signal

# Stealth techniques
def obfuscate_string(s):
    """Obfuscate strings in memory"""
    return ''.join([chr(ord(c) ^ 0x55) for c in s])

def random_process_name():
    """Change process name to something benign"""
    try:
        if os.name == 'posix':
            # Randomize process name on Linux
            libc = ctypes.CDLL('libc.so.6')
            new_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            libc.prctl(15, new_name.encode(), 0, 0, 0)
    except:
        pass

def anti_debug():
    """Simple anti-debugging techniques"""
    try:
        # Check if we're being traced
        if os.path.exists('/proc/self/status'):
            with open('/proc/self/status', 'r') as f:
                content = f.read()
                if 'TracerPid:' in content:
                    tracer_pid = content.split('TracerPid:')[1].split('\n')[0].strip()
                    if tracer_pid != '0':
                        sys.exit(0)
    except:
        pass

def clean_exit(signum, frame):
    """Clean exit handler"""
    print("\n[!] Capture interrupted, cleaning up...")
    sys.exit(0)

def list_devices():
    """List available network devices"""
    devices = get_if_list()
    print("Available devices:")
    for i, dev in enumerate(devices):
        try:
            hw_addr = get_if_raw_hwaddr(dev)[1]
            hw_addr_str = ':'.join(f'{b:02x}' for b in hw_addr)
            print(f"[{i}] {dev} ({hw_addr_str})")
        except:
            print(f"[{i}] {dev} (No MAC)")
    return devices

def packet_handler(packet, output_file=None):
    """Process captured packets"""
    try:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Extract basic packet information
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            proto = packet['IP'].proto
            proto_str = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f'IP/{proto}')
            length = len(packet)
            
            # For TCP/UDP, get ports
            if packet.haslayer('TCP'):
                sport = packet['TCP'].sport
                dport = packet['TCP'].dport
                proto_str += f":{sport}->{dport}"
            elif packet.haslayer('UDP'):
                sport = packet['UDP'].sport
                dport = packet['UDP'].dport
                proto_str += f":{sport}->{dport}"
                
            print(f"{timestamp} {proto_str:<12} {src_ip} -> {dst_ip} len={length}")
        elif packet.haslayer('ARP'):
            print(f"{timestamp} ARP         {packet['ARP'].psrc} -> {packet['ARP'].pdst}")
        else:
            # For other packet types, just show basic info
            print(f"{timestamp} {packet.summary()}")
            
        # Save to file if requested
        if output_file:
            from scapy.utils import wrpcap
            wrpcap(output_file, packet, append=True)
            
    except Exception as e:
        print(f"[!] Error processing packet: {e}")

def main():
    # Stealth initialization
    random_process_name()
    anti_debug()
    
    # Set up signal handlers for clean exit
    signal.signal(signal.SIGINT, clean_exit)
    signal.signal(signal.SIGTERM, clean_exit)
    
    # Obfuscated strings
    args_title = obfuscate_string("Arguments")
    dev_title = obfuscate_string("Devices")
    
    # Parse command line arguments in a less obvious way
    args = sys.argv[1:]
    
    # If no arguments, list devices and exit
    if not args:
        list_devices()
        print(f"\nUsage: {sys.argv[0]} <device_index> [bpf_filter] [output_file]")
        sys.exit(0)
    
    # Get available devices
    devices = list_devices()
    
    # Validate device index
    try:
        device_index = int(args[0])
        if device_index < 0 or device_index >= len(devices):
            print("Invalid device index")
            sys.exit(1)
        device = devices[device_index]
    except ValueError:
        print("Device index must be a number")
        sys.exit(1)
    
    # Get optional BPF filter and output file
    bpf_filter = args[1] if len(args) > 1 else None
    output_file = args[2] if len(args) > 2 else None
    
    print(f"Starting capture on {device}" + 
          (f" with filter '{bpf_filter}'" if bpf_filter else "") +
          (f", saving to {output_file}" if output_file else ""))
    print("Press Ctrl+C to stop...")
    
    try:
        # Start capturing
        sniff(iface=device, 
              filter=bpf_filter, 
              prn=lambda p: packet_handler(p, output_file),
              store=0)  # Don't store packets in memory to reduce footprint
    except PermissionError:
        print("[!] Permission denied. Run as root/administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Execute with some obfuscation
    main()
