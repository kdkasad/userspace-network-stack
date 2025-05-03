//! Utilities for dealing with TUN devices

use std::{
    ffi::CStr,
    fmt::Display,
    fs::{File, OpenOptions},
    net::Ipv4Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

use bitflags::bitflags;
use libc::{
    __c_anonymous_ifr_ifru, AF_INET, IFF_POINTOPOINT, IFF_TUN, IFF_TUN_EXCL, IFF_UP, Ioctl,
    SIOCGIFFLAGS, SIOCSIFADDR, SIOCSIFDSTADDR, SIOCSIFFLAGS, SOCK_DGRAM, TUNSETIFF, c_short,
    c_ushort, ifreq, in_addr, ioctl, sockaddr, sockaddr_in, socket,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

/// Represents a TUN device
pub struct TunDevice {
    pub file: File,
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
        #[allow(clippy::cast_possible_wrap)]
        let flags = u16::try_from(IFF_TUN | IFF_TUN_EXCL).unwrap() as c_short;
        let ifname = unsafe {
            ioctl_ifreq(
                file.as_raw_fd(),
                name_template,
                TUNSETIFF,
                Some(__c_anonymous_ifr_ifru { ifru_flags: flags }),
            )?
            .0
        };
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

/// Performs an `ioctl(2)` used to configure a network interface, specifically one which takes
/// a `struct ifreq` pointer as the argument.
///
/// Returns the post-ioctl name and `ifr_ifru` field of the `struct ifreq`.
///
/// # Safety
///
/// The correct field of the `data` union for the given `request` must be set.
/// Setting the wrong field for a given request is undefined behavior.
///
/// # Panics
///
/// This function panics if `name` has a value which is longer than 15 bytes.
unsafe fn ioctl_ifreq(
    fd: RawFd,
    name: Option<&str>,
    request: Ioctl,
    data: Option<__c_anonymous_ifr_ifru>,
) -> std::io::Result<(String, __c_anonymous_ifr_ifru)> {
    #[allow(clippy::cast_possible_wrap)]
    let mut ifreq = ifreq {
        ifr_name: [0; 16],
        ifr_ifru: data.unwrap_or(__c_anonymous_ifr_ifru { ifru_flags: 0 }),
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
        Ok((name, ifreq.ifr_ifru))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Set or clear the given `flag` on the given interface.
///
/// This function gets the current flag word using the `SIOCGIFFLAGS` ioctl, then either sets or
/// clears the given `flag` depending on the value of `set`, then sets the new flag word using the
/// `SIOCSIFFLAGS` ioctl.
fn ioctl_ifreq_set_flag(name: &str, flag: u16, set: bool) -> std::io::Result<()> {
    // Open a socket to perform the ioctl on
    let socket = unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    // Get current interface flags
    #[allow(clippy::cast_sign_loss)]
    let old_flags = unsafe {
        let (_name, data) = ioctl_ifreq(socket.as_raw_fd(), Some(name), SIOCGIFFLAGS, None)?;
        data.ifru_flags
    } as u16;
    // Modify and set new flags
    let new_flags = if set {
        old_flags | flag
    } else {
        old_flags & !flag
    };
    if old_flags != new_flags {
        unsafe {
            ioctl_ifreq(
                socket.as_raw_fd(),
                Some(name),
                SIOCSIFFLAGS,
                Some(__c_anonymous_ifr_ifru {
                    #[allow(clippy::cast_possible_wrap)]
                    ifru_flags: new_flags as i16,
                }),
            )?;
        }
    }
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum SetAddrType {
    Local,
    P2pDest,
}

fn ioctl_ifreq_set_addr(name: &str, addr_type: SetAddrType, addr: Ipv4Addr) -> std::io::Result<()> {
    // Open a socket to perform the ioctl on
    let socket = unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    // Create sockaddr representing given IPv4 address
    let sockaddr: sockaddr = unsafe {
        std::mem::transmute(sockaddr_in {
            sin_family: c_ushort::try_from(AF_INET).unwrap(),
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: addr.to_bits().swap_bytes(),
            },
            sin_zero: [0; 8],
        })
    };
    let (request, data) = match addr_type {
        SetAddrType::Local => (
            SIOCSIFADDR,
            __c_anonymous_ifr_ifru {
                ifru_addr: sockaddr,
            },
        ),
        SetAddrType::P2pDest => (
            SIOCSIFDSTADDR,
            __c_anonymous_ifr_ifru {
                ifru_dstaddr: sockaddr,
            },
        ),
    };
    unsafe { ioctl_ifreq(socket.as_raw_fd(), Some(name), request, Some(data))? };
    Ok(())
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
        ioctl_ifreq_set_flag(self.name(), u16::try_from(IFF_UP).unwrap(), up)
    }

    /// Sets the point-to-point flag on this interface (`IFF_POINTTOPOINT`).
    ///
    /// # Errors
    ///
    /// Returns an `Err` if getting the current state or setting the new state fail.
    fn set_p2p(&mut self, p2p: bool) -> std::io::Result<()> {
        ioctl_ifreq_set_flag(self.name(), u16::try_from(IFF_POINTOPOINT).unwrap(), p2p)
    }

    /// Set this machine's IPv4 address on the interface.
    ///
    /// # Errors
    ///
    /// Retunrns an `Err` if the operation fails.
    fn set_address(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        ioctl_ifreq_set_addr(self.name(), SetAddrType::Local, addr)
    }

    /// Set the destination address of a peer-to-peer device.
    ///
    /// # Errors
    ///
    /// Retunrns an `Err` if the operation fails.
    fn set_p2p_dst_address(&mut self, addr: Ipv4Addr) -> std::io::Result<()> {
        ioctl_ifreq_set_addr(self.name(), SetAddrType::P2pDest, addr)
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
