use std::{io::Read, net::Ipv4Addr};

use ethertype::EtherType;
use unet::tun::{NetworkInterface, TunDevice, TunPacketMetadata};
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
        let (metadata, packet) = TunPacketMetadata::try_ref_from_prefix(&buf[0..n_read])
            .expect("Packet buffer not convertible into TunPacketMetadata");
        println!("Read {n_read} bytes (4 metadata + {} packet)", n_read - 4);
        let flags = metadata.flags;
        println!("Flags: {}", flags);
        if let Some(description) = EtherType::from(metadata.protocol.get()).description() {
            println!("Protocol: {description}");
        } else {
            println!("Protocol: {:04x}", metadata.protocol);
        }
        for row in packet.chunks(16) {
            for byte in row {
                print!("{byte:02x} ");
            }
            println!();
        }
        println!();
    }
}
