use std::io::Read;

use unet::tun::{NetworkInterface, TunDevice};

pub fn main() {
    let mut tun = TunDevice::create(None).expect("Failed to create TUN interface");
    tun.set_running(true).expect("Failed to enable TUN device");
    loop {
        let mut buf = [0u8; 40];
        let n_read = tun.read(&mut buf).expect("Failed to read from device");
        println!("Read {n_read} bytes:");
        for row in buf[0..n_read].chunks(16) {
            for byte in row {
                print!("{byte:02x} ");
            }
            println!();
        }
    }
}
