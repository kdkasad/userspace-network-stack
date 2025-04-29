//! Utilities for dealing with TUN devices

use std::{
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    ops::{Deref, DerefMut},
    os::fd::AsRawFd,
};

use zerocopy::IntoBytes;

/// Represents a TUN device
pub struct TunDevice {
    file: File,
    name: CString,
}

impl TunDevice {
    /// Creates a new transient TUN device.
    ///
    /// Since this device is transient (not persistent), it will be owned by the current process
    /// and closed/removed once the returned [`TunDevice`] is dropped.
    ///
    /// The `name_template` can be:
    /// - `None`, in which case the kernel will choose the name;
    /// - the desired name of the new device;
    /// - a name template containing a `%d` placeholder, which will be replaced with the lowest
    ///   available number to create a new unique device name.
    ///
    /// This function ensures that the named TUN device is created by this operation, and will not
    /// open an existing TUN device.
    ///
    /// # Errors
    ///
    /// Returns `Err` if opening `/dev/net/tun` fails or if the `ioctl(2)` call used to create
    /// a new TUN device fails.
    ///
    /// # Panics
    ///
    /// This function panics if `name_template` contains a string which is longer than 15 bytes
    /// (not characters!).
    pub fn create(name_template: Option<&str>) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let ifname = ioctl_create_tun(file.as_raw_fd(), name_template, true)?;
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
///
/// # Panics
///
/// This function panics if `name_template` has a value which is longer than 15 bytes.
fn ioctl_create_tun(
    fd: i32,
    name_template: Option<&str>,
    exclusive: bool,
) -> std::io::Result<CString> {
    use libc::{
        __c_anonymous_ifr_ifru, IFF_TUN, IFF_TUN_EXCL, TUNSETIFF, c_short, c_ushort, ifreq, ioctl,
    };

    #[allow(clippy::cast_possible_wrap)]
    let flags =
        c_ushort::try_from(IFF_TUN | if exclusive { IFF_TUN_EXCL } else { 0 }).unwrap() as c_short;
    let mut ifreq = ifreq {
        ifr_name: [0; 16],
        ifr_ifru: __c_anonymous_ifr_ifru { ifru_flags: flags },
    };

    if let Some(template) = name_template {
        let bytes = template.as_bytes();
        assert!(bytes.len() < ifreq.ifr_name.len());
        // SAFETY: template will exist, and the length is known to be less than the length of
        // the name field of the ifreq. Since the length of the template is strictly less than the
        // `ifr_name` field, the resulting `ifr_name` is guaranteed to be null-terminated.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<i8>(),
                ifreq.ifr_name.as_mut_ptr(),
                bytes.len(),
            );
        }
    }
    let result = unsafe {
        // SAFETY: This ioctl request takes a pointer to a struct ifreq.
        ioctl(fd, TUNSETIFF, &raw mut ifreq)
    };
    if result == 0 {
        #[allow(clippy::cast_sign_loss)]
        let returned_name_buf = ifreq.ifr_name.as_bytes();
        Ok(CStr::from_bytes_until_nul(returned_name_buf)
            .expect("Returned interface name is not null-terminated")
            .to_owned())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
