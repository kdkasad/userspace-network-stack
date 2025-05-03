use std::{collections::HashMap, fmt::Display, net::Ipv4Addr, num::NonZeroUsize};

use bitflags::bitflags;
use bytes::Bytes;
use rangemap::RangeMap;
use static_assertions::const_assert_eq;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned, network_endian};

// An IPv4 header (without options) should be 20 bytes.
const IPV4_HEADER_SIZE: usize = 20;
const_assert_eq!(std::mem::size_of::<Ipv4Header>(), IPV4_HEADER_SIZE);

/// Represents the header of an IPv4 packet.
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

    /// Length of this packet's payload in bytes, not including the header.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.total_length() as usize - (4 * self.ihl() as usize)
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

    /// `true` if this packet is a complete datagram.
    /// `false` if this packet is a fragment.
    #[must_use]
    #[allow(clippy::verbose_bit_mask)]
    pub fn is_complete(&self) -> bool {
        // Checks that the fragment offset and the MF flag are zero.
        (self.flags_and_fragment_offset & 0b0011_1111_1111_1111) == 0
    }
}

bitflags! {
    /// IPv4 packet flags type.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct Ipv4Flags: u8 {
        const RESERVED = 0b100;
        const DONT_FRAGMENT = 0b010;
        const MORE_FRAGMENTS = 0b001;
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
            _ => Err(value),
        }
    }
}

/// Identifies a fragmented IPv4 packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FragmentedPacketIdentifier {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    identification: u16,
    protocol: u8,
}

impl Display for FragmentedPacketIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{{} -> {}, id 0x{:x}, proto 0x{:x}}}",
            self.src_addr, self.dst_addr, self.identification, self.protocol
        )
    }
}

impl From<&Ipv4Header> for FragmentedPacketIdentifier {
    fn from(value: &Ipv4Header) -> Self {
        Self {
            src_addr: value.src_addr(),
            dst_addr: value.dst_addr(),
            identification: value.identification(),
            protocol: value.protocol(),
        }
    }
}

#[derive(Clone, Debug)]
struct FragmentedPacket {
    header: Option<Ipv4Header>,
    payload_parts: RangeMap<usize, Bytes>,
    total_payload_len: Option<NonZeroUsize>,
    filled_bytes: usize,
}

impl Default for FragmentedPacket {
    fn default() -> Self {
        Self {
            header: None,
            payload_parts: RangeMap::new(),
            total_payload_len: None,
            filled_bytes: 0,
        }
    }
}

impl FragmentedPacket {
    /// Fill in the fragment represented by the given header and payload.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if
    /// - the given fragment overlaps with another fragment of the same datagram;
    /// - the fragment being added causes the length of the built-up payload to exceed the length
    ///   it should be according to the last fragment.
    ///
    /// # Panics
    ///
    /// Panics if `header.payload_len() != payload.len()`.
    fn add_fragment(&mut self, header: Ipv4Header, payload: Bytes) -> Result<(), FragmentError> {
        // Offset and end of this fragment in bytes
        let this_frag_off = header.fragment_offset() as usize * 8;
        let this_frag_end = this_frag_off + header.payload_len();
        let this_frag_len = this_frag_end - this_frag_off;
        let this_frag_range = this_frag_off..this_frag_end;
        assert_eq!(this_frag_len, payload.len());

        // Make sure this fragment doesn't overlap
        if self.payload_parts.overlaps(&this_frag_range) {
            return Err(FragmentError::OverlappingFragments);
        }

        // Store this fragment's payload
        self.payload_parts.insert(this_frag_range, payload);
        self.filled_bytes += this_frag_len;

        // If this is the last fragment, update the total length.
        if !header.flags().contains(Ipv4Flags::MORE_FRAGMENTS) {
            if let Ok(len) = NonZeroUsize::try_from(this_frag_end) {
                self.total_payload_len = Some(len);
            } else {
                return Err(FragmentError::LengthMismatch {
                    expected: 0,
                    actual: self.payload_parts.last_range_value().unwrap().0.end,
                });
            }
            let mut assembled_header = header;
            // Set fragment offset to 0
            assembled_header.flags_and_fragment_offset &= 0b1110_0000_0000_0000;
            // Set total length to match reassembled length
            if this_frag_end + IPV4_HEADER_SIZE > u16::MAX as usize {
                return Err(FragmentError::TooLong(this_frag_end + IPV4_HEADER_SIZE));
            }
            let total_len = u16::try_from(this_frag_end + IPV4_HEADER_SIZE).unwrap();
            assembled_header.total_length = total_len.into();
            self.header = Some(assembled_header);
        }

        // Check for length mismatches
        if let (Some(expected), Some((last_range, _))) = (
            self.total_payload_len,
            self.payload_parts.last_range_value(),
        ) {
            let actual = last_range.end;
            if actual > expected.get() {
                return Err(FragmentError::LengthMismatch {
                    expected: expected.get(),
                    actual,
                });
            }
        }

        Ok(())
    }

    /// `true` if this packet has all fragments assembled, otherwise `false`.
    fn is_complete(&self) -> bool {
        self.total_payload_len
            .is_some_and(|len| len.get() == self.filled_bytes)
    }

    /// Returns an IPv4 header and payload representing the entire reassembled packet.
    fn into_packet(self) -> Option<AssembledPacket> {
        if self.is_complete() {
            Some((
                self.header.unwrap(),
                self.payload_parts.into_iter().map(|(_k, v)| v).collect(),
            ))
        } else {
            None
        }
    }
}

/// Error type for packet fragment operations.
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum FragmentError {
    #[error("Fragment ranges overlap")]
    OverlappingFragments,

    #[error(
        "Accumulated payload length doesn't match the length given by the last fragment. Expected {expected}, got {actual}."
    )]
    LengthMismatch { expected: usize, actual: usize },

    #[error(
        "Datagram (+ header) length of {0} exceeded the maximum length representable in an IPv4 header"
    )]
    TooLong(usize),
}

/// IPv4 packet reassembler.
///
/// Takes in packets (fragmented or not) and returns complete reassembled packets.
///
/// # To do
///
/// The reassembler will currently wait forever for packets to become assembled.
/// Some sort of garbage collection needs to be done to remove packets that are not likely to be
/// completed, i.e. ones for which no fragment has arrived recently.
#[derive(Debug, Default)]
pub struct Ipv4Reassembler {
    in_progress_packets: HashMap<FragmentedPacketIdentifier, FragmentedPacket>,
}

type AssembledPacket = (Ipv4Header, Box<[Bytes]>);

impl Ipv4Reassembler {
    /// Process the given packet represented by a header and payload.
    ///
    /// If there was no error processing the packet, the function returns an optional packet.
    /// If the given packet was a complete (non-fragmented packet), or was the last fragment of an
    /// in-progress fragmented packet, the complete reassembled packet is returned. If the given
    /// packet is an incomplete fragment, `None` is returned.
    ///
    /// # Errors
    ///
    /// This function returns an `Err` if the given packet fragment was in some way invalid.
    ///
    /// # Panics
    ///
    /// Panics if `header.payload_len() != payload.len()`.
    pub fn process_packet(
        &mut self,
        header: Ipv4Header,
        data: Bytes,
    ) -> Result<Option<AssembledPacket>, FragmentError> {
        if header.is_complete() {
            Ok(Some((header, Box::new([data]))))
        } else {
            let ident = FragmentedPacketIdentifier::from(&header);
            let frag_pkt = self.in_progress_packets.entry(ident).or_default();
            frag_pkt.add_fragment(header, data)?;
            if frag_pkt.is_complete() {
                let assembled_packet = self
                    .in_progress_packets
                    .remove(&ident)
                    .unwrap()
                    .into_packet()
                    .unwrap();
                Ok(Some(assembled_packet))
            } else {
                Ok(None)
            }
        }
    }
}

/// Error type for packet reassembly operations.
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum ReassemblyError {
    #[error("fragment error in packet {0}: {1}")]
    FragmentError(FragmentedPacketIdentifier, FragmentError),
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use bytes::Bytes;
    use zerocopy::FromZeros;

    use crate::ipv4::IPV4_HEADER_SIZE;

    use super::{Ipv4Header, Ipv4Reassembler};

    #[test]
    fn reassemble_two_fragments() {
        let fragments: Vec<Vec<u8>> = vec![
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![11, 12, 13, 14, 15, 16, 17, 18],
        ];
        test_reassemble_fragments(&fragments);
    }

    /// Reassemble 8192 fragments which add up to a total datagram length of 65,515
    /// (`u16::MAX - IPV4_HEADER_SIZE`).
    /// This is the maximum reassembled datagram length we support.
    #[test]
    fn reassemble_max_fragments() {
        const DATAGRAM_LEN: usize = 65515;
        const N_FRAGMENTS: usize = DATAGRAM_LEN.div_ceil(8);
        let mut byte: u8 = 0;
        let mut fragments = Vec::with_capacity(N_FRAGMENTS);
        for i in 0..N_FRAGMENTS {
            let mut fragment = Vec::with_capacity(if i < (N_FRAGMENTS - 1) {
                8
            } else {
                DATAGRAM_LEN % 8
            });
            for _ in 0..fragment.capacity() {
                fragment.push(byte);
                byte = byte.wrapping_add(1);
            }
            fragments.push(fragment);
        }
        test_reassemble_fragments(&fragments);
    }

    /// Creates packets from the given fragments, gives them to the reassembler, and ensures the
    /// resulting reassembled packet matches the concatenation of the fragments.
    fn test_reassemble_fragments(fragments: &[Vec<u8>]) {
        let mut reassembler = Ipv4Reassembler::default();
        let mut offset: usize = 0;
        for (i, fragment) in fragments.iter().enumerate() {
            let payload = Bytes::copy_from_slice(fragment);
            let header = {
                let mut hdr = Ipv4Header::new_zeroed();
                let mut ffo = u16::try_from(offset / 8).unwrap() & 0b0001_1111_1111_1111;
                if i < fragments.len() - 1 {
                    ffo |= 0b0010_0000_0000_0000;
                }
                hdr.flags_and_fragment_offset = ffo.into();
                hdr.total_length = u16::try_from(payload.len() + IPV4_HEADER_SIZE)
                    .unwrap()
                    .into();
                hdr.version_and_ihl = (4 << 4) | 5;
                hdr
            };
            offset += payload.len();
            eprintln!(
                "Processing packet {} {}",
                header.fragment_offset() * 8,
                header.payload_len()
            );
            let maybe_packet = reassembler.process_packet(header, payload).unwrap();
            if i < fragments.len() - 1 {
                assert!(maybe_packet.is_none());
            } else {
                let (assembled_header, assembled_payload) = maybe_packet.unwrap();
                assert_eq!(
                    assembled_header.payload_len(),
                    fragments.iter().map(Vec::len).sum()
                );
                for (expected, actual) in zip(
                    fragments.iter().flatten().copied(),
                    assembled_payload.iter().flatten().copied(),
                ) {
                    assert_eq!(expected, actual);
                }
            }
        }
    }
}
