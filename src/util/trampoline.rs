use anyhow::Result;
use winapi::{
    shared::minwindef::DWORD,
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAlloc, VirtualProtect},
        processthreadsapi::{FlushInstructionCache, GetCurrentProcess},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    },
};

use crate::util::logger;

pub unsafe fn place(
    target: *mut std::os::raw::c_void,
    hook: *mut std::os::raw::c_void,
) -> Result<*mut std::os::raw::c_void> {
    if target.is_null() || hook.is_null() {
        return Err(anyhow::anyhow!("Null pointer provided"));
    }

    let mut oldprotect: DWORD = 0;

    if VirtualProtect(
        target as *mut winapi::ctypes::c_void,
        14,
        PAGE_EXECUTE_READWRITE,
        &mut oldprotect,
    ) == 0
    {
        let error = GetLastError();
        return Err(anyhow::anyhow!("Failed to change memory protection: {}", error));
    }

    let mut original = [0u8; 14];
    std::ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), 14);

    let mut jump = [0u8; 14];
    jump[0] = 0xFF; // JMP
    jump[1] = 0x25; // [RIP+0]
    jump[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let hookaddr = hook as u64;
    jump[6..14].copy_from_slice(&hookaddr.to_le_bytes());

    std::ptr::copy_nonoverlapping(jump.as_ptr(), target as *mut u8, 14);

    let trampoline = VirtualAlloc(
        std::ptr::null_mut(),
        28,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if trampoline.is_null() {
        std::ptr::copy_nonoverlapping(original.as_ptr(), target as *mut u8, 14);
        VirtualProtect(
            target as *mut winapi::ctypes::c_void,
            14,
            oldprotect,
            &mut oldprotect,
        );
        let error = GetLastError();
        return Err(anyhow::anyhow!("Failed to allocate trampoline: {}", error));
    }

    std::ptr::copy_nonoverlapping(original.as_ptr(), trampoline as *mut u8, 14);

    let mut jumpback = [0u8; 14];
    jumpback[0] = 0xFF;
    jumpback[1] = 0x25;
    jumpback[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let returnaddr = (target as u64) + 14;
    jumpback[6..14].copy_from_slice(&returnaddr.to_le_bytes());

    std::ptr::copy_nonoverlapping(jumpback.as_ptr(), (trampoline as *mut u8).offset(14), 14);

    VirtualProtect(
        target as *mut winapi::ctypes::c_void,
        14,
        oldprotect,
        &mut oldprotect,
    );

    FlushInstructionCache(
        GetCurrentProcess(),
        target as *mut winapi::ctypes::c_void,
        14,
    );
    FlushInstructionCache(
        GetCurrentProcess(),
        trampoline as *mut winapi::ctypes::c_void,
        28,
    );

    logger::debug(&format!(
        "Trampoline: Target=0x{:016X}, Hook=0x{:016X}, Trampoline=0x{:016X}",
        target as usize, hook as usize, trampoline as usize
    ));

    Ok(trampoline as *mut std::os::raw::c_void)
}