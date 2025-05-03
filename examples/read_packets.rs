use std::{io::Read, net::Ipv4Addr};

use ethertype::EtherType;
use unet::{
    ipv4::{Ipv4Header, Ipv4TransportProtocol},
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

    loop {
        let mut buf = [0u8; 4096];
        let n_read = tun.read(&mut buf).expect("Failed to read from device");
        let (metadata, packet_bytes) = TunPacketMetadata::try_ref_from_prefix(&buf[0..n_read])
            .expect("Packet buffer not convertible into TunPacketMetadata");
        println!("Read {n_read} bytes (4 metadata + {} packet)", n_read - 4);
        let flags = metadata.flags;
        println!("Flags: {}", flags);
        if let Some(description) = EtherType::from(metadata.protocol.get()).description() {
            println!("Protocol: {description}");
        } else {
            println!("Protocol: {:04x}", metadata.protocol);
        }

        // Attempt to parse IPv4 packet
        if metadata.protocol.get() == ethertype::consts::IPV4.0 {
            match Ipv4Header::try_ref_from_prefix(packet_bytes) {
                Ok((header, rest)) => {
                    println!("From: {}", header.src_addr());
                    println!("To: {}", header.dst_addr());
                    if let Ok(proto) = Ipv4TransportProtocol::try_from(header.protocol()) {
                        println!("Transport protocol: {}", proto.long_name());
                    }
                    hex_dump(rest);
                }
                Err(err) => {
                    println!("Failed to convert packet buffer to Ipv4Packet type: {err}");
                }
            }
        } else {
            hex_dump(packet_bytes);
        }
        println!();
    }
}

fn hex_dump(bytes: &[u8]) {
    for row in bytes.chunks(16) {
        for byte in row {
            print!("{byte:02x} ");
        }
        println!();
    }
}
