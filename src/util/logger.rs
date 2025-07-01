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
        fileapi::{CreateFileA, CreateFileW, WriteFile, OPEN_ALWAYS, OPEN_EXISTING},
        handleapi::INVALID_HANDLE_VALUE,
        shlobj::{SHGetFolderPathW, CSIDL_DESKTOP},
        wincon::GetConsoleWindow,
        winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_WRITE, HANDLE},
    },
};

static LOGHANDLE: Mutex<Option<usize>> = Mutex::new(None);

pub unsafe fn init() {
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
                success("Console allocated");
                if let Some(path) = createdirs() {
                    success(&format!("Created directories: {}", path.display()));
                    if createlog(&path) {
                        success("Log file created");
                        write("[+] Fracture logging initialized");
                    } else {
                        error("Failed to create log file");
                    }
                } else {
                    error("Failed to create directories");
                }
            }
        }
    }
}

fn createdirs() -> Option<PathBuf> {
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
            let mut fracturepath = PathBuf::from(desktop);

            fracturepath.push("fracture");
            fracturepath.push("logs");

            if std::fs::create_dir_all(&fracturepath).is_err() {
                return None;
            }

            fracturepath.push("fracture.log");
            Some(fracturepath)
        } else {
            None
        }
    }
}

unsafe fn createlog(path: &PathBuf) -> bool {
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
        *LOGHANDLE.lock().unwrap() = Some(handle as usize);
        true
    } else {
        false
    }
}

pub fn write(message: &str) {
    unsafe {
        let guard = LOGHANDLE.lock().unwrap();
        if let Some(handleaddr) = *guard {
            let handle = handleaddr as HANDLE;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let logmessage = format!("[{}] {}\r\n", timestamp, message);
            let mut written = 0;

            WriteFile(
                handle,
                logmessage.as_ptr() as *const winapi::ctypes::c_void,
                logmessage.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            );
        }
    }
}

pub fn success(message: &str) {
    let msg = format!("[+] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn error(message: &str) {
    let msg = format!("[!] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn info(message: &str) {
    let msg = format!("[?] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn hook(message: &str) {
    let msg = format!("[→] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn method(message: &str) {
    let msg = format!("    {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn debug(message: &str) {
    let msg = format!("[*] {}", message);
    println!("{}", msg);
    write(&msg);
}