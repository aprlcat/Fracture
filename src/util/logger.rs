use std::{
    ffi::OsString,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    sync::Mutex,
};

use winapi::{
    shared::winerror::S_OK,
    um::{
        consoleapi::AllocConsole,
        fileapi::{CreateFileA, CreateFileW, OPEN_ALWAYS, OPEN_EXISTING, WriteFile},
        handleapi::INVALID_HANDLE_VALUE,
        shlobj::{CSIDL_DESKTOP, SHGetFolderPathW},
        wincon::GetConsoleWindow,
        winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE, HANDLE},
    },
};

static LOG_HANDLE: Mutex<Option<usize>> = Mutex::new(None);

pub unsafe fn setup() {
    if GetConsoleWindow().is_null() {
        if AllocConsole() != 0 {
            let stdout = CreateFileA(
                b"CONOUT$\0".as_ptr() as *const i8,
                GENERIC_WRITE,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );

            if stdout != INVALID_HANDLE_VALUE {
                println!("[+] Console allocated successfully");

                match create_directories() {
                    Some(path) => {
                        println!("[+] Created fracture directories: {}", path.display());
                        if create_logfile(&path) {
                            println!("[+] Log file created successfully");
                            write("[+] Fracture logging initialized");
                        } else {
                            println!("[!] Failed to create log file");
                        }
                    }
                    None => {
                        println!("[!] Failed to create fracture directories");
                    }
                }
            }
        }
    }
}

fn create_directories() -> Option<PathBuf> {
    unsafe {
        let mut path = [0u16; 260];
        if SHGetFolderPathW(
            std::ptr::null_mut(),
            CSIDL_DESKTOP,
            std::ptr::null_mut(),
            0,
            path.as_mut_ptr(),
        ) == S_OK
        {
            let len = path.iter().position(|&x| x == 0).unwrap_or(path.len());
            let desktop = OsString::from_wide(&path[..len]);
            let mut fracture_path = PathBuf::from(desktop);

            fracture_path.push("fracture");
            fracture_path.push("logs");

            if let Err(e) = std::fs::create_dir_all(&fracture_path) {
                println!("[!] Failed to create directories: {}", e);
                return None;
            }

            fracture_path.push("fracture.log");
            Some(fracture_path)
        } else {
            println!("[!] Failed to get desktop path");
            None
        }
    }
}

unsafe fn create_logfile(path: &PathBuf) -> bool {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = CreateFileW(
        wide.as_ptr(),
        GENERIC_WRITE,
        0,
        std::ptr::null_mut(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut(),
    );

    if handle != INVALID_HANDLE_VALUE {
        *LOG_HANDLE.lock().unwrap() = Some(handle as usize);
        true
    } else {
        println!(
            "[!] Failed to create log file, error: {}",
            winapi::um::errhandlingapi::GetLastError()
        );
        false
    }
}

pub fn write(message: &str) {
    unsafe {
        let guard = LOG_HANDLE.lock().unwrap();
        if let Some(handle_addr) = *guard {
            let handle = handle_addr as HANDLE;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let log_message = format!("[{}] {}\r\n", timestamp, message);
            let mut written = 0;

            let result = WriteFile(
                handle,
                log_message.as_ptr() as *const winapi::ctypes::c_void,
                log_message.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );

            if result == 0 {
                println!("[!] Failed to write to log file");
            }
        }
    }
}
