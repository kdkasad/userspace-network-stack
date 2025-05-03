//! Miscellaneous utilities

use std::io::{self, Read};

use bytes::BytesMut;

/// Attempts to read from the given `reader`, appending the data to the `buf`, up to the existing capacity.
/// The capacity will not change due to this operation.
///
/// If `buf.len() == buf.capacity()`, then `reader.read()` is not called.
///
/// Once stabilized, [`Read::read_buf()`] will make this obsolete.
/// This helper exists as a poly-fill for that functionality.
///
/// # Errors
///
/// Same as [`Read::read()`].
pub fn extend_from_reader<R>(buf: &mut BytesMut, reader: &mut R) -> io::Result<usize>
where
    R: Read,
{
    let space = buf.spare_capacity_mut();
    if space.is_empty() {
        return Ok(0);
    }
    unsafe {
        let space_assume_init = &mut *(std::ptr::from_mut(space) as *mut [u8]);
        reader.read(space_assume_init).inspect(|&n_read| {
            buf.set_len(buf.len() + n_read);
        })
    }
}
