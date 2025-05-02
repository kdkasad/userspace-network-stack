use std::net::Ipv4Addr;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned, network_endian};

#[derive(Copy, Clone, Debug, Unaligned, KnownLayout, FromBytes, Immutable)]
#[repr(C, packed)]
pub struct Ipv4Header {
    version_and_ihl: u8,
    dcsp_and_ecn: u8,
    total_length: network_endian::U16,
    identification: network_endian::U16,
    flags_and_fragment_offset: network_endian::U16,
    ttl: u8,
    protocol: u8,
    header_checksum: network_endian::U16,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

impl Ipv4Header {
    /// Internet protocol version.
    /// Should always be 4 for IPv4.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version_and_ihl >> 4
    }

    /// Internet header length.
    ///
    /// The length of this packet's IPv4 header in multiples of 32 bits.
    /// E.g., an IHL of 5 means a 20-byte (160-bit) header.
    #[must_use]
    pub fn ihl(&self) -> u8 {
        self.version_and_ihl & 0b1111
    }

    /// `true` if this packet has [options] and `false` otherwise.
    ///
    /// [options]: https://en.wikipedia.org/wiki/IPv4#Options
    #[must_use]
    pub fn has_options(&self) -> bool {
        self.ihl() > 5
    }

    /// [Differentiated services code point][dcsp]
    ///
    /// [dcsp]: https://en.wikipedia.org/wiki/Differentiated_Services_Code_Point
    #[must_use]
    pub fn dcsp(&self) -> u8 {
        self.dcsp_and_ecn >> 2
    }

    /// [Explicit congestion notification][wiki]
    ///
    /// [wiki]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    #[must_use]
    pub fn ecn(&self) -> u8 {
        self.dcsp_and_ecn & 0b11
    }

    /// Total packet size in bytes, including header and data.
    #[must_use]
    pub fn total_length(&self) -> u16 {
        self.total_length.get()
    }

    /// Identification field.
    /// Used for re-assembling fragmented packets.
    #[must_use]
    pub fn identification(&self) -> u16 {
        self.identification.get()
    }

    /// Packet flags.
    #[must_use]
    pub fn flags(&self) -> Ipv4Flags {
        Ipv4Flags::from_bits_retain(self.flags_and_fragment_offset.to_bytes()[0] >> 5)
    }

    /// Offset of this fragment relative to the beginning of the original unfragmented datagram,
    /// in units of 8 bytes.
    ///
    /// E.g., a fragment offset of 6 means this packet contains the fragment of the original
    /// datagram starting 48 bytes after the start of the unfragmented payload.
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        self.flags_and_fragment_offset.get() & 0b0001_1111_1111_1111
    }

    /// Time to live.
    /// Technically represents a value in seconds, but in practice, represents routing hops.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    /// Transport layer protocol contained in this IP datagram.
    ///
    /// See <https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers>.
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Header checksum value.
    ///
    /// See <https://en.wikipedia.org/wiki/IPv4#Header_checksum>.
    #[must_use]
    pub fn header_checksum(&self) -> u16 {
        self.header_checksum.get()
    }

    /// Source address, i.e. the address of the packet's sender.
    #[must_use]
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.src_addr)
    }

    /// Destination address.
    #[must_use]
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_addr)
    }
}

bitflags! {
    pub struct Ipv4Flags: u8 {
        const RESERVED = 0b100;
        const DONT_FRAGMENT = 0b010;
        const MORE_FRAGMENTS = 0b100;
    }
}

/// Represents the transport protocol contained in an IPv4 packet.
///
/// Currently contains the values from [Wikipedia's list of common payload
/// protocols](https://en.wikipedia.org/wiki/IPv4#Protocol).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv4TransportProtocol {
    /// Internet Control Message Protocol
    Icmp = 1,
    /// Internet Group Management Protocol
    Igmp = 2,
    /// Transmission Control Protocol
    Tcp = 6,
    /// User Datagram Protocol
    Udp = 17,
    /// IPv6 encapsulation
    Encap = 41,
    /// Open Shortest Path First
    Ospf = 89,
    /// Stream Control Transmission Protocol
    Sctp = 132,
}

impl Ipv4TransportProtocol {
    #[must_use]
    pub fn short_name(&self) -> &'static str {
        match self {
            Ipv4TransportProtocol::Icmp => "ICMP",
            Ipv4TransportProtocol::Igmp => "IGMP",
            Ipv4TransportProtocol::Tcp => "TCP",
            Ipv4TransportProtocol::Udp => "UDP",
            Ipv4TransportProtocol::Encap => "ENCAP",
            Ipv4TransportProtocol::Ospf => "OSPF",
            Ipv4TransportProtocol::Sctp => "SCTP",
        }
    }

    #[must_use]
    pub fn long_name(&self) -> &'static str {
        match self {
            Ipv4TransportProtocol::Icmp => "Internet Control Message Protocol",
            Ipv4TransportProtocol::Igmp => "Internet Group Management Protocol",
            Ipv4TransportProtocol::Tcp => "Transmission Control Protocol",
            Ipv4TransportProtocol::Udp => "User Datagram Protocol",
            Ipv4TransportProtocol::Encap => "IPv6 Encapsulation",
            Ipv4TransportProtocol::Ospf => "Open Shortest Path First",
            Ipv4TransportProtocol::Sctp => "Stream Control Transmission Protocol",
        }
    }
}

impl TryFrom<u8> for Ipv4TransportProtocol {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Ipv4TransportProtocol::Icmp),
            2 => Ok(Ipv4TransportProtocol::Igmp),
            6 => Ok(Ipv4TransportProtocol::Tcp),
            17 => Ok(Ipv4TransportProtocol::Udp),
            41 => Ok(Ipv4TransportProtocol::Encap),
            89 => Ok(Ipv4TransportProtocol::Ospf),
            132 => Ok(Ipv4TransportProtocol::Sctp),
            _ => Err(value)
        }
    }
}
