#[doc(hidden)]
mod iocp;
#[doc(hidden)]
mod ioctl;
#[doc(hidden)]
mod utils;

use std::ffi::CString;
use std::net::UdpSocket;
use std::string::String;
use winapi::um::winnt::HANDLE;

use utils::{get_tun_guid, strerror, CanSend, Handle};

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
/// * Connect them to each other
/// * Start a new thread
/// * On the new thread, splice the TUN handle and one of the sockets
/// * Register the other socket to wepoll
///
pub struct Tun {
    sock: Option<UdpSocket>,
}

#[doc(hidden)]
fn parse_packet<'a>(buf: &'a [u8]) -> Result<&'a [u8], String> {
    Ok(&buf[0..1])
}

#[doc(hidden)]
fn send_packet(sock: &UdpSocket, pkt: Result<&[u8], String>) -> Result<(), String> {
    Ok(())
}

#[doc(hidden)]
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

        let mut tun_reading = false;
        let mut sock_reading = false;
        loop {
            if !tun_reading {
                tun_overlapped = std::mem::zeroed();
                if ReadFile(
                    tun_hdl.get(),
                    tun_buf.as_mut_ptr() as *mut c_void,
                    tun_buf.len() as u32,
                    null_mut(),
                    &mut tun_overlapped,
                ) != 0
                {
                    assert!(false);
                }
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
                tun_reading = true;
            }

            if !sock_reading {
                sock_overlapped = std::mem::zeroed();
                if ReadFile(
                    sock_hdl,
                    sock_buf.as_mut_ptr() as *mut c_void,
                    sock_buf.len() as u32,
                    null_mut(),
                    &mut sock_overlapped,
                ) != 0
                {
                    assert!(false);
                }
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
                sock_reading = true;
            }

            // IOCP wait
            if tun_reading || sock_reading {
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
                    tun_reading = false;
                    let p = &tun_buf[0..len as usize];
                    println!("Received packet: {:?}", p);
                    /*
                    if let Ok(pkt) = packet::ip::Packet::new(p) {
                        println!("Received IP packet: {:?}", pkt);
                    } else if let Ok(pkt) = packet::icmp::Packet::new(p) {
                        println!("Received ICMP packet: {:?}", pkt);
                    }
                    */

                    if p.len() > mtu {
                        // TODO: Drop or ICMP
                    } else {
                        send_packet(&sock, Ok(p)).unwrap();
                    }
                } else {
                    sock_reading = false;
                    match parse_packet(&sock_buf[0..len as usize]) {
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
                                return;
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
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
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
            return Err(format!("MTU too large: {}", mtu));
        }

        let guid = get_tun_guid(name)?;

        let path = CString::new(format!("\\\\.\\Global\\{}.tap", guid)).unwrap();
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

        // Addr and mask in small-end
        let addrv = addr.octets();
        let addri = (addrv[0] as u32)
            | ((addrv[1] as u32) << 8)
            | ((addrv[2] as u32) << 16)
            | ((addrv[3] as u32) << 24);
        let mask = ((1u64 << prefix_len) - 1) as u32;
        if let Err(err) = ioctl::config_tun(handle.get(), addri, addri & mask, mask) {
            return Err(format!(
                "Failed to config TUN with error: {}",
                strerror(err)
            ));
        }

        let output = std::process::Command::new("netsh")
            .arg("interface")
            .arg("ip")
            .arg("set")
            .arg("address")
            .arg(name)
            .arg("static")
            .arg(addr.to_string())
            .arg(
                std::net::Ipv4Addr::from(((1u32 << prefix_len) - 1) << (32 - prefix_len))
                    .to_string(),
            )
            .output()
            .map_err(|e| {
                format!(
                    "Failed to execute netsh command to set TUN interface address with error: {}",
                    e
                )
            })?;

        if !output.status.success() {
            return Err(format!(
                "Failed to execute netsh command to set TUN interface address with output: {}",
                String::from_utf8(output.stderr)
                    .unwrap_or_else(|e| format!("OUTPUT NOT UTF-8: {}", e))
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
