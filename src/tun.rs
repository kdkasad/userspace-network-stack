//! Utilities for dealing with TUN devices

use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
};

/// Represents a TUN device
pub struct TunDevice {
    file: File,
    name: CString,
}

impl TunDevice {
    /// Attempts to create a new [`TunDevice`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if opening `/dev/net/tun` fails, or if the `ioctl(2)` call used to create
    /// a new TUN device fails.
    pub fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let ifname = ioctl_create_tun(file.as_raw_fd())?;
        Ok(Self { file, name: ifname })
    }

    /// Returns the name of the TUN interface
    #[must_use]
    pub fn name(&self) -> &CStr {
        self.name.as_c_str()
    }
}

/// Allow dereferencing a [`TunDevice`] into a [`File`]
impl Deref for TunDevice {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

/// Allow dereferencing a [`TunDevice`] into a [`File`]
impl DerefMut for TunDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

/// Performs the `ioctl(2)` call which creates a TUN device.
///
/// The `fd` argument must be a file descriptor referring to `/dev/net/tun`.
fn ioctl_create_tun(fd: i32) -> std::io::Result<CString> {
    use libc::{__c_anonymous_ifr_ifru, IFF_TUN, TUNSETIFF, c_short, ifreq, ioctl};

    const NAME_TEMPLATE: &[u8; 5] = b"tun%d";

    let mut ifreq = ifreq {
        ifr_name: [0; 16],
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_flags: c_short::try_from(IFF_TUN).unwrap(),
        },
    };
    assert!(NAME_TEMPLATE.len() < ifreq.ifr_name.len());
    let result = unsafe {
        // SAFETY: NAME_TEMPLATE will exist, and the length is known to be less than the length of
        // the name field of the ifreq.
        std::ptr::copy_nonoverlapping(
            NAME_TEMPLATE.as_ptr().cast::<i8>(),
            ifreq.ifr_name.as_mut_ptr(),
            NAME_TEMPLATE.len(),
        );

        // SAFETY: This ioctl request takes a pointer to a struct ifreq.
        ioctl(fd, TUNSETIFF, &raw mut ifreq)
    };
    if result == 0 {
        #[allow(clippy::cast_sign_loss)]
        let name = ifreq.ifr_name.map(|c| c as u8);
        Ok(CStr::from_bytes_until_nul(&name)
            .expect("Returned interface name is not null-terminated")
            .to_owned())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
