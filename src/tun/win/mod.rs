mod ioctl;

use std::ffi::CString;
use std::string::String;
use winapi::um::winnt::HANDLE;

/// The TUN interface to use
///
/// # Usage
/// `Tun` implements [Read](https://doc.rust-lang.org/nightly/std/io/trait.Read.html) and
/// [Write](https://doc.rust-lang.org/nightly/std/io/trait.Write.html) traits and can be used to
/// read and write packets.
///
/// However, due to the special nature of a TUN interface, only the basic `read` and `write`
/// methods should be used and every `read` should read at least MTU bytes and every `write`
/// at most MTU bytes.
pub struct Tun {
    mtu: usize,
    handle: HANDLE,
}

fn strerror(errno: u32) -> String {
    let mut buff: [i8; 1024] = [0; 1024];
    unsafe {
        use std::ptr::null_mut;
        use winapi::um::winbase::FormatMessageA;
        use winapi::um::winbase::FORMAT_MESSAGE_FROM_SYSTEM;

        FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM,
            null_mut(),
            errno,
            0,
            buff.as_mut_ptr(),
            1024,
            null_mut(),
        );
    }
    String::from_utf8(
        buff.iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect(),
    )
    .unwrap_or(format!("Failed to format error: {}", errno))
}

impl Tun {
    /// Open a TUN interface using {ID} and set its address and mtu
    ///
    /// # Arguments
    ///
    /// * `name` - The interface id in the form of `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`
    /// * `addr` - The address to set on the interface
    /// * `prefix_len` - The length of the mask prefix (0 ~ 32)
    /// * `mtu` - The MTU for the interface (<= 1500)
    ///
    /// # Note
    ///
    /// The mtu set upon the interface will be implemented by utilizing [Path MTU
    /// Discovery](https://en.wikipedia.org/wiki/Path_MTU_Discovery) of the Windows OS by sending ICMP
    /// back through the TUN when packet too large is received.
    pub fn open(
        name: &str,
        addr: std::net::Ipv4Addr,
        prefix_len: usize,
        mtu: usize,
    ) -> Result<Tun, String> {
        use winapi::um::handleapi::CloseHandle;

        if prefix_len > 32 {
            return Err(format!("Invalid prefix length: {}", prefix_len));
        }

        if mtu > 1500 {
            return Err(format!("Invalid MTU: {}", mtu));
        }

        let path = CString::new(format!("\\\\.\\Global\\{}.tap", name)).unwrap();
        let handle;
        unsafe {
            use std::ptr::null_mut;
            use winapi::um::errhandlingapi::GetLastError;
            use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
            use winapi::um::handleapi::INVALID_HANDLE_VALUE;
            use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
            use winapi::um::winnt::{
                FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
                GENERIC_WRITE,
            };

            handle = CreateFileA(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                return Err(format!(
                    "Failed to create TUN file with error: {}",
                    strerror(err)
                ));
            }
        }

        if let Err(err) = ioctl::set_media_status(handle, true) {
            unsafe {
                CloseHandle(handle);
            }
            return Err(format!(
                "Failed to set media status with error: {}",
                strerror(err)
            ));
        }

        let addr = u32::from(addr);
        let mask: u32 = (((1u64 << prefix_len) - 1) << (32 - prefix_len)) as u32;
        if let Err(err) = ioctl::config_tun(handle, addr, addr & mask, mask) {
            unsafe {
                CloseHandle(handle);
            }
            return Err(format!(
                "Failed to config TUN with error: {}",
                strerror(err)
            ));
        }

        Ok(Tun {
            mtu: mtu,
            handle: handle,
        })
    }
}

impl std::io::Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::{Error, ErrorKind};

        if buf.len() < self.mtu {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Read buffer must be at least MTU {} bytes long", self.mtu),
            ));
        }

        let ret: usize;
        unsafe {
            use std::ffi::c_void;
            use std::ptr::null_mut;
            use winapi::shared::minwindef::DWORD;
            use winapi::shared::winerror::ERROR_IO_PENDING;
            use winapi::um::errhandlingapi::GetLastError;
            use winapi::um::fileapi::ReadFile;
            use winapi::um::handleapi::CloseHandle;
            use winapi::um::ioapiset::GetOverlappedResult;
            use winapi::um::minwinbase::OVERLAPPED;
            use winapi::um::synchapi::CreateEventA;

            let event = CreateEventA(null_mut(), 0, 0, null_mut());
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = event;

            let mut num_read: DWORD = 0;
            if ReadFile(
                self.handle,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut num_read,
                &mut overlapped,
            ) == 0
            {
                if GetLastError() != ERROR_IO_PENDING {
                    CloseHandle(event);
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Failed to read from TUN with error: {}",
                            strerror(GetLastError())
                        ),
                    ));
                }

                num_read = 0;
                if GetOverlappedResult(self.handle, &mut overlapped, &mut num_read, 1) == 0 {
                    CloseHandle(event);
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Failed to wait for async read with error: {}",
                            strerror(GetLastError())
                        ),
                    ));
                }
            }

            ret = num_read as usize;
        }

        Ok(ret)
    }
}
