# Red Team Tool - XDP Packet Dropper

## Ryan Schanzenbacher - Bravo Team

### Getting Started

To run this tool, get a Linux (newer than kernel 4.9) system running. First, we need to mount the bpf kernel directory that will be hooked into later.

```
mount -t bpf bpf /sys/fs/bpf
```

This command should return no errors. Next, ensure the package xdp-loader is installed. This package is provided in `xdp-tools`. Finally, load the driver on the interface you want to "attack" (found using `ip a`).

```
xdp-loader load {interface_name} packet_dropper_new.o
```

### Usage

Now that the driver is loaded, it is active. Nothing will appear to have changed on the host system (however if you run `ip a` now you will see a new "xdp" entry after the interface mtu. On a separate system, craft an IP packet with the source address equal to `223.255.254.115` and the destination equal to the computer with the tainted interface. There can be any payload encapsulated within the IP packet, this is discarded. A sample python script utilizing scapy has been provided. Or, you can send a legitimate ICMP packet with the type of 2 to trigger the payload as well. An example C program has been included showing this. When this packet is sent, all IP communication from the tainted interface will be blocked, effectively disabling the computers communication with the outside world. Note: Layer 2 communication (like ARP) will still be allowed to ensure connectivity can be restored. If you send the specially crafted packet again, IP communication will be allowed through again, like a toggle.

### Build information

A prebuild version has been provided, however to build you can do the following. You need the linux headers, libbpf headers, libxdp headers and clang. Once you have all of these installed, run the following command to build the object file that can be loaded:

```
clang -O2 -g -Wall -target bpf -c packet_dropper_new.c -o packet_dropper_new.o
```

