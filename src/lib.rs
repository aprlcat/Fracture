#![allow(unsafe_op_in_unsafe_fn)]

use winapi::{
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
    um::{
        handleapi::CloseHandle, libloaderapi::DisableThreadLibraryCalls,
        processthreadsapi::CreateThread, winnt::DLL_PROCESS_ATTACH,
    },
};

mod jvm;
mod util;

use jvm::hook::start;
use util::logger::setup;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(h_module: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                DisableThreadLibraryCalls(h_module);
                setup();

                let thread = CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(hookthread),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                );

                if !thread.is_null() {
                    CloseHandle(thread);
                }
            }
            TRUE
        }
        _ => TRUE,
    }
}

unsafe extern "system" fn hookthread(_param: LPVOID) -> DWORD {
    match start() {
        Ok(_) => {
            println!("[+] JNI hook initialized successfully");
            0
        }
        Err(e) => {
            println!("[!] Failed to initialize JNI hook: {}", e);
            1
        }
    }
}
