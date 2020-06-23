mod ioctl;

use std::ffi::CString;
use std::net::UdpSocket;
use std::string::String;
use winapi::um::winnt::HANDLE;

/// The TUN interface to use
///
/// # Usage
///
/// `Tun` implements [`AsRawSocket`](https://doc.rust-lang.org/std/os/windows/io/trait.AsRawSocket.html)
/// so it can be used with multiplexing frameworks.
///
/// # Internal
///
/// Because major rust async frameworks uses [wepoll](https://github.com/piscisaureus/wepoll), it
/// can't work with TUN interface handle.
///
/// The following work around is created:
/// * Create two UDP sockets
/// * Start a new thread
/// * On the new thread, connect the TUN handle and one of the sockets
/// * Register the other socket to wepoll
///
pub struct Tun {
    sock: Option<UdpSocket>,
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

fn parse_packet<'a>(buf: &'a [u8]) -> Result<&'a [u8], String> {
    Err("XXX".to_string())
}

fn send_packet(sock: &UdpSocket, pkt: Result<&[u8], String>) -> Result<(), String> {
    Err("XXX".to_string())
}

struct CanSend<T>(T);
unsafe impl<T> Send for CanSend<T> {}

struct Handle {
    hdl: HANDLE,
    taken: bool,
}

impl Drop for Handle {
    fn drop(&mut self) {
        use winapi::um::handleapi::CloseHandle;

        if !self.taken {
            unsafe {
                CloseHandle(self.take());
            }
        }
    }
}

impl Handle {
    fn new(h: HANDLE) -> Handle {
        Handle {
            hdl: h,
            taken: false,
        }
    }

    fn get(&self) -> HANDLE {
        self.hdl
    }

    fn take(&mut self) -> HANDLE {
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;

        let hdl = self.hdl;
        self.hdl = INVALID_HANDLE_VALUE;
        self.taken = true;
        hdl
    }
}

fn worker_main(tun_hdl: CanSend<HANDLE>, mtu: usize, sock: UdpSocket) {
    unsafe {
        use std::ffi::c_void;
        use std::os::windows::io::{AsRawSocket, RawSocket};
        use std::ptr::null_mut;
        use winapi::shared::minwindef::DWORD;
        use winapi::shared::ntdef::NULL;
        use winapi::shared::winerror::ERROR_IO_PENDING;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::fileapi::{ReadFile, WriteFile};
        use winapi::um::ioapiset::{CreateIoCompletionPort, GetQueuedCompletionStatus};
        use winapi::um::minwinbase::OVERLAPPED;
        use winapi::um::winbase::INFINITE;

        let tun_hdl = Handle::new(tun_hdl.0);

        let iocp = CreateIoCompletionPort(tun_hdl.get(), null_mut(), 0, 1);
        if iocp == NULL {
            send_packet(
                &sock,
                Err(format!(
                    "Failed to create IOCP and associate it with TUN handle with error: {}",
                    strerror(GetLastError())
                )),
            )
            .unwrap();
            return;
        }
        let iocp = Handle::new(iocp);

        let sock_sock = sock.as_raw_socket();
        let sock_hdl = std::mem::transmute::<RawSocket, HANDLE>(sock_sock);
        if CreateIoCompletionPort(sock_hdl, iocp.get(), 1, 0) == NULL {
            send_packet(
                &sock,
                Err(format!(
                    "Failed to associate IOCP with UDP socket with error: {}",
                    strerror(GetLastError())
                )),
            )
            .unwrap();
        }

        let mut tun_overlapped: OVERLAPPED;
        let mut tun_buf: [u8; 2000] = [0; 2000];

        let mut sock_overlapped: OVERLAPPED;
        let mut sock_buf: [u8; 2000] = [0; 2000];

        let read_from_tun = |buf: &[u8], len| -> bool {
            match parse_packet(&buf[0 .. len]) {
                Ok(p) => {
                    if p.len() > mtu {
                        // Drop or ICMP
                        //TODO
                    } else {
                        send_packet(&sock, Ok(p)).unwrap();
                    }
                    true
                }
                Err(_) => false,
            }
        };

        let read_from_sock = |buf: &[u8], len| -> bool {
            match parse_packet(&buf[0..len]) {
                Ok(p) => {
                    if p.len() > mtu {
                        // Drop this packet
                        // TODO: Introduce nonfatal error?
                    }
                    let mut len: DWORD = 0;
                    // TODO: Async write
                    if WriteFile(
                        tun_hdl.get(),
                        p.as_ptr() as *const c_void,
                        p.len() as u32,
                        &mut len,
                        null_mut(),
                    ) == 0
                    {
                        send_packet(
                            &sock,
                            Err(format!(
                                "Failed to send packet to TUN with error: {}",
                                strerror(GetLastError())
                            )),
                        )
                        .unwrap();
                        false
                    } else if len != p.len() as u32 {
                        send_packet(
                            &sock,
                            Err(format!(
                                "Failed to send packet to TUN with bad length: {}/{}",
                                len,
                                p.len()
                            )),
                        )
                        .unwrap();
                        false
                    } else {
                        true
                    }
                }
                Err(_) => false,
            }
        };

        loop {
            let mut pending = 0;
            loop {
                let mut len: DWORD = 0;
                tun_overlapped = std::mem::zeroed();
                if ReadFile(
                    tun_hdl.get(),
                    tun_buf.as_mut_ptr() as *mut c_void,
                    tun_buf.len() as u32,
                    &mut len,
                    &mut tun_overlapped,
                ) == 0
                {
                    let err = GetLastError();
                    if err != ERROR_IO_PENDING {
                        send_packet(
                            &sock,
                            Err(format!(
                                "Failed to read packet from TUN with error: {}",
                                strerror(err)
                            )),
                        )
                        .unwrap();
                        return;
                    }

                    // Read pending
                    pending += 1;
                    break;
                } else if len == 0 {
                    send_packet(&sock, Err("Empty read from TUN".to_string())).unwrap();
                    return;
                } else {
                    if !read_from_tun(&tun_buf, len as usize) {
                        return;
                    }
                }
            }

            loop {
                let mut len: DWORD = 0;
                sock_overlapped = std::mem::zeroed();
                if ReadFile(
                    sock_hdl,
                    sock_buf.as_mut_ptr() as *mut c_void,
                    sock_buf.len() as u32,
                    &mut len,
                    &mut sock_overlapped,
                ) == 0
                {
                    let err = GetLastError();
                    if err != ERROR_IO_PENDING {
                        send_packet(
                            &sock,
                            Err(format!(
                                "Failed to read packet from UDP socket with error: {}",
                                strerror(err)
                            )),
                        )
                        .unwrap();
                        return;
                    }

                    // Read pending
                    pending += 1;
                    break;
                } else if len == 0 {
                    send_packet(&sock, Err("Empty packet from UDP socket".to_string())).unwrap();
                    return;
                } else {
                    if !read_from_sock(&sock_buf, len as usize) {
                        return;
                    }
                }
            }

            // IOCP wait
            while pending > 0 {
                let mut len: DWORD = 0;
                let mut key: usize = 0;
                let mut olp: *mut OVERLAPPED = null_mut();
                if GetQueuedCompletionStatus(iocp.get(), &mut len, &mut key, &mut olp, INFINITE)
                    == 0
                {
                    send_packet(
                        &sock,
                        Err(format!(
                            "Failed to wait for IO completion with error: {}",
                            strerror(GetLastError())
                        )),
                    )
                    .unwrap();
                    return;
                }

                if key == 0 {
                    if !read_from_tun(&tun_buf, len as usize) {
                        return;
                    }
                } else {
                    if !read_from_sock(&sock_buf, len as usize) {
                        return;
                    }
                }

                pending -= 1;
            }
        }
    }
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
        if prefix_len > 32 {
            return Err(format!("Invalid prefix length: {}", prefix_len));
        }

        if mtu > 1500 {
            return Err(format!("Invalid MTU: {}", mtu));
        }

        let path = CString::new(format!("\\\\.\\Global\\{}.tap", name)).unwrap();
        let mut handle = unsafe {
            use std::ptr::null_mut;
            use winapi::um::errhandlingapi::GetLastError;
            use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
            use winapi::um::handleapi::INVALID_HANDLE_VALUE;
            use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
            use winapi::um::winnt::{
                FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
                GENERIC_WRITE,
            };

            let handle = CreateFileA(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(format!(
                    "Failed to create TUN file with error: {}",
                    strerror(GetLastError())
                ));
            }

            Handle::new(handle)
        };

        if let Err(err) = ioctl::set_media_status(handle.get(), true) {
            return Err(format!(
                "Failed to set media status with error: {}",
                strerror(err)
            ));
        }

        let addr = u32::from(addr);
        let mask: u32 = (((1u64 << prefix_len) - 1) << (32 - prefix_len)) as u32;
        if let Err(err) = ioctl::config_tun(handle.get(), addr, addr & mask, mask) {
            return Err(format!(
                "Failed to config TUN with error: {}",
                strerror(err)
            ));
        }

        let inner_sock = std::net::UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to create inner UDP socket with error: {}", e))?;

        let outer_sock = std::net::UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to create outer UDP socket with error: {}", e))?;

        let addr = outer_sock.local_addr().map_err(|e| {
            format!(
                "Failed to get bound address of outer UDP socket with error: {}",
                e
            )
        })?;

        inner_sock.connect(addr).map_err(|e| {
            format!(
                "Failed to connect inner UDP socket to outer with error: {}",
                e
            )
        })?;

        let addr = inner_sock.local_addr().map_err(|e| {
            format!(
                "Failed to get bound address of inner UDP socket with error: {}",
                e
            )
        })?;

        outer_sock.connect(addr).map_err(|e| {
            format!(
                "Failed to connect outer UDP socket to inner with error: {}",
                e
            )
        })?;

        let handle = CanSend(handle.take());
        std::thread::spawn(move || worker_main(handle, mtu, inner_sock));

        Ok(Tun {
            sock: Some(outer_sock),
        })
    }

    /*
    /// Receive a packet from TUN
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
    }

    /// Send a packet to TUN
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
    }
    */
}

impl Drop for Tun {
    fn drop(&mut self) {
        if let Some(sock) = &self.sock {
            send_packet(sock, Err("Closed".to_string())).unwrap();
        }
    }
}
