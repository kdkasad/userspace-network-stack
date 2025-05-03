use std::{io::Read, net::Ipv4Addr};

use bytes::{Bytes, BytesMut};
use unet::{
    ipv4::{Ipv4Header, Ipv4Reassembler, Ipv4TransportProtocol},
    tun::{NetworkInterface, TunDevice, TunPacketMetadata},
};
use zerocopy::TryFromBytes;

pub fn main() {
    let mut tun = TunDevice::create(None).expect("Failed to create TUN interface");
    tun.set_running(true).expect("Failed to enable TUN device");
    tun.set_p2p(true).expect("Failed to set TUN device as P2P");
    tun.set_address(Ipv4Addr::new(10, 0, 0, 1))
        .expect("Failed to set address");
    tun.set_p2p_dst_address(Ipv4Addr::new(10, 0, 0, 2))
        .expect("Failed to set peer address");

    let mut reassembler = Ipv4Reassembler::default();
    loop {
        // Read packet into a byte buffer
        let mut buf = BytesMut::with_capacity(4096);
        buf.resize(4096, 0); // Inefficient but oh well...
        let n_read = tun.read(buf.as_mut()).expect("Failed to read from device");
        buf.truncate(n_read);
        let buf = buf.freeze();

        let (metadata, packet_bytes) = TunPacketMetadata::try_read_from_prefix(&buf)
            .expect("Packet buffer not convertible into TunPacketMetadata");
        let packet_bytes = buf.slice_ref(packet_bytes);
        println!("Read {n_read} bytes (4 metadata + {} packet)", n_read - 4);
        // Attempt to parse IPv4 packet
        if metadata.protocol.get() == ethertype::consts::IPV4.0 {
            match Ipv4Header::try_read_from_prefix(&packet_bytes) {
                Ok((header, rest)) => {
                    if header.payload_len() != rest.len() {
                        println!("Header length doesn't match actual length. Skipping packet.");
                        continue;
                    }
                    match reassembler.process_packet(header, buf.slice_ref(rest)) {
                        Ok(Some((header, payload))) => print_packet(&header, &payload),
                        Ok(None) => (),
                        Err(err) => eprintln!("Error reassembling packet: {err}"),
                    }
                }
                Err(err) => {
                    println!("Failed to convert packet buffer to Ipv4Packet type: {err}");
                }
            }
        } else {
            println!("Ignoring non-IPv4 packet");
        }
        println!();
    }
}

fn print_packet(header: &Ipv4Header, payload: &[Bytes]) {
    println!("From: {}", header.src_addr());
    println!("To: {}", header.dst_addr());
    if let Ok(proto) = Ipv4TransportProtocol::try_from(header.protocol()) {
        println!("Transport protocol: {}", proto.long_name());
    }
    println!("Length: {}", header.payload_len());
    for (i, byte) in payload.iter().flatten().enumerate() {
        print!("{byte:02x} ");
        if i % 16 == 15 {
            println!();
        }
    }
}
