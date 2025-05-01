//! Utilities for dealing with TUN devices

use std::{
    ffi::CStr, fmt::Display, fs::{File, OpenOptions}, ops::{Deref, DerefMut}, os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd}
};

use bitflags::bitflags;
use ethertype::EtherType;
use libc::{
    __c_anonymous_ifr_ifru, AF_INET, IFF_TUN, IFF_TUN_EXCL, IFF_UP, Ioctl, SIOCGIFFLAGS,
    SIOCSIFFLAGS, SOCK_DGRAM, TUNSETIFF, c_short, c_ushort, ifreq, ioctl, socket,
};
use zerocopy::{network_endian, FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

/// Represents a TUN device
pub struct TunDevice {
    file: File,
    name: String,
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
        let flags = u16::try_from(IFF_TUN | IFF_TUN_EXCL).unwrap();
        let (ifname, _flags) =
            ifreq_ioctl(file.as_raw_fd(), name_template, TUNSETIFF, Some(flags))?;
        Ok(Self { file, name: ifname })
    }
}

impl NetworkInterface for TunDevice {
    /// Returns the name of the TUN interface
    #[must_use]
    fn name(&self) -> &str {
        &self.name
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.file.as_raw_fd()
    }
}

/// Support dereferencing a [`TunDevice`] into a [`File`]
impl Deref for TunDevice {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

/// Support dereferencing a [`TunDevice`] into a [`File`]
impl DerefMut for TunDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

/// Performs an `ioctl(2)` used to configure a network interface, specifically one which takes
/// a `struct ifreq` pointer as the argument and makes use of the `ifr_name` and `ifr_flags`
/// fields.
///
/// Returns the post-ioctl name and flags of the `struct ifreq`, as some ioctls modify those.
/// See `netdevice(7)`.
///
/// # Panics
///
/// This function panics if `name` has a value which is longer than 15 bytes.
fn ifreq_ioctl(
    fd: RawFd,
    name: Option<&str>,
    request: Ioctl,
    flags: Option<c_ushort>,
) -> std::io::Result<(String, u16)> {
    #[allow(clippy::cast_possible_wrap)]
    let mut ifreq = ifreq {
        ifr_name: [0; 16],
        ifr_ifru: __c_anonymous_ifr_ifru {
            ifru_flags: flags.unwrap_or(0) as c_short,
        },
    };

    if let Some(name_str) = name {
        let name_bytes = name_str.as_bytes();
        assert!(name_bytes.len() < ifreq.ifr_name.len());
        // SAFETY: template will exist, and the length is known to be less than the length of
        // the name field of the ifreq. Since the length of the template is strictly less than the
        // `ifr_name` field, the resulting `ifr_name` is guaranteed to be null-terminated.
        unsafe {
            std::ptr::copy_nonoverlapping(
                name_bytes.as_ptr().cast::<i8>(),
                ifreq.ifr_name.as_mut_ptr(),
                name_bytes.len(),
            );
        }
    }
    let result = unsafe {
        // SAFETY: This ioctl request takes a pointer to a struct ifreq.
        ioctl(fd, request, &raw mut ifreq)
    };
    if result == 0 {
        #[allow(clippy::cast_sign_loss)]
        let returned_name_buf = ifreq.ifr_name.as_bytes();
        let name = CStr::from_bytes_until_nul(returned_name_buf)
            .expect("Returned interface name is not null-terminated")
            .to_str()
            .expect("Returned interface name is not valid UTF-8")
            .to_owned();
        let flags = unsafe { ifreq.ifr_ifru.ifru_flags };
        #[allow(clippy::cast_sign_loss)]
        Ok((name, flags as c_ushort))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Trait to provide operations for network interfaces.
pub trait NetworkInterface: AsRawFd {
    /// Returns the name of the interface.
    #[must_use]
    fn name(&self) -> &str;

    /// Sets the running state of the interface (i.e. the `IFF_UP`) flag.
    ///
    /// # Errors
    ///
    /// Returns an `Err` if getting the current state or setting the new state fail.
    fn set_running(&mut self, up: bool) -> std::io::Result<()> {
        // Open a socket to perform the ioctl on
        let socket = unsafe {
            let fd = socket(AF_INET, SOCK_DGRAM, 0);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            OwnedFd::from_raw_fd(fd)
        };
        // Get current interface flags
        let (_name, old_flags) =
            ifreq_ioctl(socket.as_raw_fd(), Some(self.name()), SIOCGIFFLAGS, None)?;
        // Modify and set new flags
        let iff_up = c_ushort::try_from(IFF_UP).unwrap();
        let new_flags = if up {
            old_flags | iff_up
        } else {
            old_flags & !iff_up
        };
        if old_flags != new_flags {
            ifreq_ioctl(
                socket.as_raw_fd(),
                Some(self.name()),
                SIOCSIFFLAGS,
                Some(new_flags),
            )?;
        }
        Ok(())
    }
}

/// Type for dealing with TUN packet flags.
#[repr(transparent)]
#[derive(KnownLayout, Immutable, FromBytes, Copy, Clone, Debug, PartialEq, Eq)]
pub struct TunPacketFlags(u16);

bitflags! {
    /// Flags set on each packet read from the TUN interface (when `TUN_NO_PI` is not set).
    impl TunPacketFlags: u16 {
        /// The complete packet did not fit in the buffer and will be striped across multiple reads.
        const TUN_PKT_STRIP = 1 << 0;
    }
}

impl Display for TunPacketFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

/// Metadata added to packets read from the TUN device.
#[repr(C, packed)]
#[derive(KnownLayout, Immutable, FromBytes, Copy, Clone, Debug, PartialEq, Eq, Unaligned)]
pub struct TunPacketMetadata {
    pub flags: TunPacketFlags,
    pub protocol: network_endian::U16,
}
