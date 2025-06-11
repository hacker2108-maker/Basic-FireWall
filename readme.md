# Advanced Linux Kernel Firewall

## Overview

This project implements an advanced firewall as a Linux kernel module with a companion userspace control utility. The firewall provides:

- Stateful packet filtering (connection tracking)
- Support for TCP, UDP, and ICMP protocols
- Rate limiting capabilities
- Detailed logging
- Comprehensive statistics
- Flexible rule management

## Features

### Core Functionality
- Kernel-level packet filtering for maximum performance
- Stateful inspection with connection tracking
- Support for inbound, outbound, and forwarded traffic
- Multiple action types: ACCEPT, DROP, REJECT, LOG

### Rule System
- Match by source/destination IP (with netmask support)
- Match by source/destination port
- Protocol filtering (TCP/UDP/ICMP/ALL)
- Interface matching (input/output)
- Connection state matching (NEW/ESTABLISHED/RELATED/INVALID)
- Rate limiting per IP address

### Management Interface
- Character device for communication between kernel and userspace
- IOCTL-based control interface
- Userspace CLI tool for rule management
- Real-time statistics collection
- Detailed packet logging

## Components

1. **Kernel Module (advanced_firewall.ko)**
   - Implements the core firewall functionality
   - Netfilter hooks for packet inspection
   - Connection tracking system
   - Rule processing engine
   - Logging and statistics collection

2. **Userspace Tool (firewallctl)**
   - Command-line interface for firewall management
   - Rule addition/deletion/listing
   - Statistics viewing/resetting
   - Log viewing/flushing

## Installation

### Prerequisites
- Linux kernel headers
- GCC compiler
- Make tool

### Installation Steps

1. Clone or download the project files
2. Run the installer:
  
   sudo ./install.sh
   
3. The installer will:
   - Build the kernel module
   - Load the module
   - Install the userspace tool
   - Set up device nodes
   - Optionally configure auto-load at boot

## Usage

### Basic Commands

# Add a rule (see rule format below)
firewallctl -a "direction=in action=drop protocol=tcp dst_port=22"

# Delete a rule by ID
firewallctl -d 1

# Clear all rules
firewallctl -c

# Show statistics
firewallctl -s

# Show log
firewallctl -l

# Flush log
firewallctl -f

# Reset statistics
firewallctl -r
### Rule Format

Rules are specified as space-separated key=value pairs:

direction=in|out|forward 
action=accept|drop|reject|log 
protocol=all|tcp|udp|icmp 
src_ip=IP[/mask] 
dst_ip=IP[/mask] 
src_port=PORT 
dst_port=PORT 
flags=established|new|related|invalid 
rate_limit=N 
iface_in=INTERFACE 
iface_out=INTERFACE
### Examples

1. Block incoming SSH:
  
   firewallctl -a "direction=in action=drop protocol=tcp dst_port=22"
   
2. Allow established connections:
  
   firewallctl -a "direction=in action=accept flags=established"
   
3. Rate limit HTTP connections:
  
   firewallctl -a "direction=in action=drop protocol=tcp dst_port=80 rate_limit=60"
   
4. Log all outgoing DNS queries:
  
   firewallctl -a "direction=out action=log protocol=udp dst_port=53"
   
## Technical Details

### Kernel Module Internals
- Uses Netfilter hooks for packet inspection
- Implements connection tracking using a hash table
- Rule matching is optimized for performance
- Locking used for thread-safe operation
- Workqueues for deferred log processing

### Userspace-Kernel Communication
- Character device (/dev/advanced_firewall)
- IOCTL-based interface for control operations
- File operations for log access

## Building Manually

make                # Build both module and tool
make clean          # Clean build artifacts
sudo make install   # Install module and tool
sudo make uninstall # Remove module and tool
## TroubleshootModule fails to loado load**
   - Check dmesg for error messages
   - Verify kernel headers are installed
   - Ensure no other firewall is conflicting
   
   2. Rules not working
   - Check rule syntax carefully
   - Verify rule direction matches traffic flow
   - Check log for packet processing information

  3. Performance issues
   - Minimize number of rules
   - Place frequently matched rules first
   - Use specific matches rather than broad ones

## License

This project is licensed under the GPL v2 license. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please submit issues or pull requests through GitHub.

## Author

HACKER2108 - Cliffpressoir5@gmail.com