use std::mem::transmute;
use winapi::shared::minwindef::DWORD;
use winapi::um::winioctl::{CTL_CODE, FILE_ANY_ACCESS, FILE_DEVICE_NETWORK, METHOD_BUFFERED};
use winapi::um::winnt::HANDLE;

fn tap_win_ctrl_code(request: DWORD, method: DWORD) -> DWORD {
    CTL_CODE(FILE_DEVICE_NETWORK, request, method, FILE_ANY_ACCESS)
}

fn ioctl(
    handle: HANDLE,
    ctrl: DWORD,
    input: Option<&[u8]>,
    output: Option<&mut [u8]>,
) -> Result<(), u32> {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use winapi::shared::winerror::*;
    use winapi::um::ioapiset::DeviceIoControl;

    let mut input_ptr: *mut c_void = null_mut();
    let mut input_len: DWORD = 0;
    if let Some(i) = input {
        input_ptr = i.as_ptr() as *mut c_void;
        input_len = i.len() as DWORD;
    }

    let mut output_ptr: *mut c_void = null_mut();
    let mut output_len: DWORD = 0;
    if let Some(o) = output {
        output_ptr = o.as_mut_ptr() as *mut c_void;
        output_len = o.len() as DWORD;
    }

    let mut output_ret_len: DWORD = 0;

    let err = unsafe {
        DeviceIoControl(
            handle,
            ctrl,
            input_ptr,
            input_len,
            output_ptr,
            output_len,
            &mut output_ret_len,
            null_mut(),
        )
    };

    if (err as u32) != ERROR_SUCCESS {
        Err(err as u32)
    } else {
        Ok(())
    }
}

pub fn get_mac(handle: HANDLE) -> Result<[u8; 6], u32> {
    let mut mac: [u8; 6] = [0; 6];
    ioctl(
        handle,
        tap_win_ctrl_code(1, METHOD_BUFFERED),
        None,
        Some(&mut mac),
    )
    .map(|_| mac)
}

#[derive(Debug)]
pub struct Version {
    major: u32,
    minor: u32,
    dbg: u32,
}

pub fn get_version(handle: HANDLE) -> Result<Version, u32> {
    let mut output: [u8; 12] = [0; 12];
    ioctl(
        handle,
        tap_win_ctrl_code(2, METHOD_BUFFERED),
        None,
        Some(&mut output),
    )
    .map(|_| {
        let output = unsafe { transmute::<[u8; 12], [u32; 3]>(output) };
        Version {
            major: output[0],
            minor: output[1],
            dbg: output[2],
        }
    })
}

pub fn get_mtu(handle: HANDLE) -> Result<u32, u32> {
    let mut output: [u8; 4] = [0; 4];
    ioctl(
        handle,
        tap_win_ctrl_code(3, METHOD_BUFFERED),
        None,
        Some(&mut output),
    )
    .map(|_| unsafe { transmute::<[u8; 4], u32>(output) })
}

pub fn config_tun(
    handle: HANDLE,
    local_ip: u32,
    remote_network: u32,
    remote_netmask: u32,
) -> Result<(), u32> {
    let input: [u32; 3] = [local_ip, remote_network, remote_netmask];
    let input = unsafe { transmute::<[u32; 3], [u8; 12]>(input) };
    ioctl(
        handle,
        tap_win_ctrl_code(10, METHOD_BUFFERED),
        Some(&input),
        None,
    )
}

pub fn config_point_to_point(
    handle: HANDLE,
    local_ip: u32,
    remote_network: u32,
) -> Result<(), u32> {
    let input: [u32; 2] = [local_ip, remote_network];
    let input = unsafe { transmute::<[u32; 2], [u8; 8]>(input) };
    ioctl(
        handle,
        tap_win_ctrl_code(5, METHOD_BUFFERED),
        Some(&input),
        None,
    )
}

pub fn config_dhcp_msaq(
    handle: HANDLE,
    dhcp_addr: u32,
    dhcp_netmask: u32,
    dhcp_server_ip: u32,
    dhcp_lease_time: u32,
) -> Result<(), u32> {
    let input: [u32; 4] = [dhcp_addr, dhcp_netmask, dhcp_server_ip, dhcp_lease_time];
    let input = unsafe { transmute::<[u32; 4], [u8; 16]>(input) };
    ioctl(
        handle,
        tap_win_ctrl_code(7, METHOD_BUFFERED),
        Some(&input),
        None,
    )
}

pub fn config_dhcp_set_opt(handle: HANDLE, option: &[u8]) -> Result<(), u32> {
    ioctl(
        handle,
        tap_win_ctrl_code(9, METHOD_BUFFERED),
        Some(option),
        None,
    )
}

pub fn get_info(handle: HANDLE) -> Result<String, u32> {
    let mut output: [u8; 1024] = [0; 1024];
    ioctl(
        handle,
        tap_win_ctrl_code(4, METHOD_BUFFERED),
        None,
        Some(&mut output),
    )
    .map(|_| String::from_utf8(output.to_vec()).unwrap())
}

pub fn set_media_status(handle: HANDLE, status: bool) -> Result<(), u32> {
    let input: u32 = status as u32;
    let input = unsafe { transmute::<u32, [u8; 4]>(input) };
    ioctl(
        handle,
        tap_win_ctrl_code(6, METHOD_BUFFERED),
        Some(&input),
        None,
    )
}

pub const PRIORITY_BEHAVIOR_NOPRIORITY: u32 = 0;
pub const PRIORITY_BEHAVIOR_ENABLED: u32 = 1;
pub const PRIORITY_BEHAVIOR_ADDALWAYS: u32 = 2;
pub const PRIORITY_BEHAVIOR_MAX: u32 = 2;

pub fn priority_behavior(handle: HANDLE, behavior: u32) -> Result<(), u32> {
    let input = unsafe { transmute::<u32, [u8; 4]>(behavior) };
    ioctl(
        handle,
        tap_win_ctrl_code(11, METHOD_BUFFERED),
        Some(&input),
        None,
    )
}
