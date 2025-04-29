use std::{io::Read, process::ExitCode};

use unet::tun::{NetworkInterface, TunDevice};

/// Creates a TUN device and sets its state to running.
/// If the first argument is `--wait`, it will wait for user input after creating the device but
/// before exiting to allow other programs to inspect/modify the interface.
pub fn main() -> ExitCode {
    // Attempt to create a new TUN device
    let mut tundev = match TunDevice::create(None) {
        Ok(dev) => dev,
        Err(err) => {
            eprintln!("Failed to create TUN device: {}", err);
            return ExitCode::FAILURE;
        }
    };

    // Print the name of the TUN device
    println!("New TUN device named {} created", tundev.name());

    // Enable interface
    if let Err(err) = tundev.set_running(true) {
        eprintln!("Failed to set {} up: {}", tundev.name(), err);
    }
    println!("Set {} running state to up", tundev.name());

    // Wait if requested
    if std::env::args().nth(1).is_some_and(|arg| arg == "--wait") {
        println!("Waiting for user input before exiting.");
        let mut buf = [0u8; 1];
        let _ = std::io::stdin().read(&mut buf).unwrap();
    }

    ExitCode::SUCCESS
}
