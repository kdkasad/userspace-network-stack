use std::process::ExitCode;

use unet::tun::TunDevice;

pub fn main() -> ExitCode {
    // Attempt to create a new TUN device
    let tundev = match TunDevice::new() {
        Ok(dev) => dev,
        Err(err) => {
            eprintln!("Failed to create TUN device: {}", err);
            return ExitCode::FAILURE;
        }
    };

    // Print the name of the TUN device
    println!(
        "New TUN device named {} created",
        tundev.name().to_string_lossy()
    );

    ExitCode::SUCCESS
}
