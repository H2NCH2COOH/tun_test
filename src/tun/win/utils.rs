use winapi::um::winnt::HANDLE;

pub fn strerror(errno: u32) -> String {
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

pub struct CanSend<T>(pub T);
unsafe impl<T> Send for CanSend<T> {}

pub struct Handle {
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
    pub fn new(h: HANDLE) -> Handle {
        Handle {
            hdl: h,
            taken: false,
        }
    }

    pub fn get(&self) -> HANDLE {
        self.hdl
    }

    pub fn take(&mut self) -> HANDLE {
        use winapi::um::handleapi::INVALID_HANDLE_VALUE;

        let hdl = self.hdl;
        self.hdl = INVALID_HANDLE_VALUE;
        self.taken = true;
        hdl
    }
}

pub fn get_tun_guid(name: &str) -> Result<String, String> {
    unsafe {
        use std::ffi::{CString, OsString};
        use std::os::windows::ffi::OsStringExt;
        use std::ptr::null_mut;
        use winapi::shared::winerror::*;
        use winapi::um::winnt::*;
        use winapi::um::winreg::*;

        let LIST_KEY = CString::new(
            "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        )
        .unwrap();
        let mut list = HKEY_LOCAL_MACHINE;
        let err = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            LIST_KEY.as_ptr(),
            0,
            KEY_READ,
            &mut list,
        ) as u32;
        if err != ERROR_SUCCESS {
            return Err(format!(
                "Failed to open list regkey with error: {}",
                strerror(err)
            ));
        }

        for idx in 0.. {
            const BUFF_SIZE: usize = 2048;
            let mut buff: [i8; BUFF_SIZE] = [0; BUFF_SIZE];
            let mut buff_len: u32 = BUFF_SIZE as u32;
            let err = RegEnumKeyExA(
                list,
                idx,
                buff.as_mut_ptr(),
                &mut buff_len,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            ) as u32;
            if err == ERROR_NO_MORE_ITEMS {
                break;
            } else if err != ERROR_SUCCESS {
                RegCloseKey(list);
                return Err(format!(
                    "Failed to enumerate subkey at {} with error: {}",
                    idx,
                    strerror(err)
                ));
            }

            if buff[0] != 123 {
                //'{'
                continue;
            }

            let guid_vec: Vec<u8> = buff
                .iter()
                .take_while(|&&i| i != 0)
                .map(|&i| i as u8)
                .collect();
            let mut key: Vec<i8> = LIST_KEY.to_bytes().iter().map(|&i| i as i8).collect();
            key.push(92); // '\'
            key.extend(guid_vec.iter().map(|&i| i as i8));
            key.extend("\\Connection".as_bytes().iter().map(|&i| i as i8));

            let guid = String::from_utf8(guid_vec).unwrap();

            let mut hkey = HKEY_LOCAL_MACHINE;
            let mut tries = 0;
            loop {
                let err =
                    RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.as_ptr(), 0, KEY_READ, &mut hkey) as u32;
                if err == ERROR_SUCCESS {
                    break;
                } else if err == ERROR_FILE_NOT_FOUND {
                    if tries < 5 {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    } else {
                        RegCloseKey(list);
                        return Err(format!("Failed to open regkey of {} with error 2", guid));
                    }
                } else {
                    RegCloseKey(list);
                    return Err(format!(
                        "Failed to open regkey of {} with error: {}",
                        guid,
                        strerror(err)
                    ));
                }
            }

            let mut buff: [u8; BUFF_SIZE] = [0; BUFF_SIZE];
            buff_len = BUFF_SIZE as u32;
            let err = RegQueryValueExW(
                hkey,
                {
                    let mut v: Vec<u16> = Vec::with_capacity(5);
                    v.push(78);  // N
                    v.push(97);  // a
                    v.push(109); // m
                    v.push(101); // e
                    v.push(0);   // NUL
                    v
                }
                .as_ptr(),
                null_mut(),
                null_mut(),
                buff.as_mut_ptr(),
                &mut buff_len,
            ) as u32;
            RegCloseKey(hkey);
            if err != ERROR_SUCCESS {
                RegCloseKey(list);
                return Err(format!(
                    "Failed to read name of interface: {} with error: {}",
                    guid,
                    strerror(err)
                ));
            }
            assert_eq!(buff_len % 2, 0);

            let len = (buff_len as usize) / 2;
            let mut wcbuff = Vec::<u16>::with_capacity(len);
            for i in 0..len {
                // Assume little-end
                let wchar = ((buff[2 * i + 1] as u16) << 8) | buff[2 * i] as u16;
                if wchar == 0 {
                    break;
                }
                wcbuff.push(wchar);
            }

            let ifname = OsString::from_wide(wcbuff.as_slice());
            if ifname == name {
                RegCloseKey(list);
                return Ok(guid);
            }
        }

        RegCloseKey(list);
    }

    Err(format!("Can't find interface {}", name))
}
