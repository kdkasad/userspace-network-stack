# Userspace network stack

A from-scratch implementation of a network stack in userspace for Linux.

## What is it?

This project implements a network stack in userspace.
Normally, the Linux kernel handles all of the low-level protocol details, and
provides a nice socket-based interface to use such protocols. For example, you
can just open a TCP socket using `socket(AF_INET, SOCK_STREAM, 0)`, and
read/write from/to the socket without caring at all how TCP (or the protocols
underlying it) work.

Instead of doing that, this project implements all of the protocol details in
userspace. It simply passes fully-constructed [L3] packets to the kernel, which
can then process them as if they came from a real network interface, like an
Ethernet port.[^l2note]

[^l2note]: Real network interfaces provide [L2] packets to the kernel. Eventually, this
project will hopefully handle the [link layer][L2] itself, but for now it
operates at [layer 3][L3] and above.

[L2]: https://en.wikipedia.org/wiki/OSI_model#Layer_2:_Data_link_layer
[L3]: https://en.wikipedia.org/wiki/OSI_model#Layer_3:_Network_layer

## How does it work?

First, we create a new TUN interface ([Wikipedia][tun:wiki],
[Linux][tun:linux]), which is a network interface that passes packets to
a userspace program instead of to a physical device. This means that from the
kernel's (and other programs') points of view, this interface is a regular
network interface like any other. It can have an address (or multiple), have
routes associated with it, etc. When a packet is routed to this TUN interface,
however, the kernel does not pass it to a hardware device, but instead provides
the packet to our program.

Our program can then take the packet, parse it, and handle the packet however it
sees fit. It can also write packets to the kernel, which causes them to be
processed and routed by the kernel, just like if a packet was received on an
Ethernet port.

Currently, we put the TUN interface in point-to-point mode, which means our TUN
interface acts as a link to a single other device, rather than a link to
a network like an Ethernet port or Wi-Fi adapter might. This tends to make sense
given how the library is used (see below); however, this is merely a design
choice and not a strict requirement. It just means that our network stack
emulates a single device rather than a network of other devices.

> [!NOTE] the following is the eventual goal of this project, and is not yet
> realized.

The userspace network stack is implemented as a library which provides
a socket-like interface that other programs can make use of. Programs can use
this library in a similar way to which they'd use the OS-level networking API;
callers can:
 - Listen for incoming connections on a TCP port
 - Connect to a remote TCP address/port
 - Use the above TCP connections as byte streams, without worrying about the
   underlying protocol or implementation.
 - Listen for incoming UDP packets on a port
 - Send UDP packets to a remote address/port

[tun:wiki]: https://en.wikipedia.org/wiki/TUN/TAP
[tun:linux]: https://www.kernel.org/doc/html/latest/networking/tuntap.html

# Roadmap

Protocols/features implemented:
- [x] IPv4
  - [x] Parsing
  - [x] Fragment reassembly
- [ ] IPv6
  - [ ] Parsing
- [ ] TCP
  - [ ] Parsing
  - [ ] Connection state handling
  - [ ] User-facing API
- [ ] UDP
  - [ ] Parsing
  - [ ] User-facing API

# Copyright, license, and contact

This project is written and copyrighted by [Kian Kasad].
It is made a available under the terms of the [Apache License 2.0].

If you have any questions about it, please reach out to me (Kian).

[Kian Kasad]: https://github.com/kdkasad
[Apache License 2.0]: https://github.com/kdkasad/userspace-network-stack/blob/master/LICENSE
