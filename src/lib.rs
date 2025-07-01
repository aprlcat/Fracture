#![allow(unsafe_op_in_unsafe_fn)]

use winapi::{
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
    um::{
        handleapi::CloseHandle,
        libloaderapi::DisableThreadLibraryCalls,
        processthreadsapi::CreateThread,
        winnt::DLL_PROCESS_ATTACH,
    },
};

mod jvm;
mod util;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                DisableThreadLibraryCalls(module);
                util::logger::init();

                let thread = CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(main),
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

unsafe extern "system" fn main(_param: LPVOID) -> DWORD {
    match jvm::hook::start() {
        Ok(_) => {
            util::logger::success("Fracture initialized successfully");
            0
        }
        Err(e) => {
            util::logger::error(&format!("Failed to initialize: {}", e));
            1
        }
    }
}