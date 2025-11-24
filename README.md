# XDP/eBPF MacSec Statistics Example

This example demonstrates an XDP/eBPF program that tracks statistics for packets with a specific encapsulation: **Ethernet/IPv6/GRE/MPLS/Ethernet/MacSec**.

## Features

1. **Packet Parsing**: Parses packet headers and passes all packets through
2. **Statistics Tracking**: For packets matching the encapsulation:
   - Counts all matching packets globally
   - Counts packets per MPLS label
   - Tracks the latest MacSec packet number seen per MPLS label
3. **User-Space Display**: Periodically reads and displays all statistics

## Requirements

- Linux kernel 5.8+ (for XDP support)
- clang/llvm (for compiling eBPF programs)
- libbpf development libraries
- bpftool (for generating skeleton)

### Install Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) bpftool
```

### Install Dependencies (RHEL/CentOS/Fedora)

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel bpftool
```

## Building

```bash
cd xdp-macsec-stats
make
```

This will generate:
- `xdp_prog.o` - The compiled eBPF program
- `xdp_prog.skel.h` - Auto-generated skeleton header
- `user_prog` - The user-space program

## Usage

Run the program as root (XDP requires elevated privileges):

```bash
sudo ./user_prog <interface_name> [interval_seconds]
```

Example:
```bash
sudo ./user_prog eth0 2
```

This will:
- Attach the XDP program to the specified interface
- Display statistics every 2 seconds
- Press Ctrl+C to stop and detach

## Output

The program displays:
- **Global Statistics**:
  - Total matching packets
  - Latest packet number seen
  
- **Per-MPLS-Label Statistics**:
  - MPLS Label
  - Packet count for that label
  - Latest packet number for that label

Example output:
```
=== Global Statistics ===
Total matching packets: 1234
Latest packet number: 5678

=== Per-MPLS-Label Statistics ===
MPLS Label      Packet Count         Latest Packet Number
-----------     ------------         ---------------------
100             500                  2500
200             734                  3500
```

## Packet Encapsulation

The program matches packets with the following structure:
- **Outer Ethernet** (14 bytes)
- **IPv6** (40 bytes, protocol 47 for GRE)
- **GRE** (4+ bytes, protocol 0x8847 for MPLS)
- **MPLS** (4 bytes)
- **[Optional] Pseudowire Control Word** (4 bytes) - see configuration below
- **Inner Ethernet** (14 bytes, EtherType 0x88E5 for MacSec)
- **MacSec** (12+ bytes)

### Pseudowire Control Word Support

The program supports an optional pseudowire control word between the MPLS label and inner Ethernet header. This is useful for lab environments where the control word is present.

To enable pseudowire control word parsing, build with:
```bash
make ENABLE_PW_CW=1
```

To disable it (default, for deployment):
```bash
make
# or explicitly
make ENABLE_PW_CW=0
```

## Notes

- The program passes all packets (returns `XDP_PASS`)
- Statistics are stored in eBPF maps and persist while the program is attached
- The MacSec packet number is extracted from the MacSec header
- MPLS label is extracted from the top 20 bits of the MPLS label field
- The program assumes a single MPLS label (simplified parsing)

## Troubleshooting

1. **Permission denied**: Run with `sudo`
2. **Interface not found**: Check interface name with `ip link`
3. **BPF program load failed**: Check kernel logs with `dmesg | tail`
4. **No statistics**: Verify packets match the expected encapsulation

## Cleanup

To remove the program:
```bash
make clean
```

To manually detach XDP program (if needed):
```bash
sudo ip link set dev <interface> xdp off
```

