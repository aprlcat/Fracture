use anyhow::Result;
use winapi::{
    shared::minwindef::DWORD,
    um::{
        memoryapi::{VirtualAlloc, VirtualProtect},
        processthreadsapi::{FlushInstructionCache, GetCurrentProcess},
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    },
};

pub unsafe fn place(
    target: *mut std::os::raw::c_void,
    hook: *mut std::os::raw::c_void,
) -> Result<*mut std::os::raw::c_void> {
    let mut old_protect: DWORD = 0;

    if VirtualProtect(
        target as *mut winapi::ctypes::c_void,
        14,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    ) == 0
    {
        return Err(anyhow::anyhow!("Failed to change memory protection"));
    }

    let mut original = [0u8; 14];
    std::ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), 14);

    let mut jump = [0u8; 14];
    jump[0] = 0xFF; // JMP
    jump[1] = 0x25; // [RIP+0]
    jump[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let hook_addr = hook as u64;
    jump[6..14].copy_from_slice(&hook_addr.to_le_bytes());

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
            old_protect,
            &mut old_protect,
        );
        return Err(anyhow::anyhow!("Failed to allocate trampoline"));
    }

    std::ptr::copy_nonoverlapping(original.as_ptr(), trampoline as *mut u8, 14);

    let mut jump_back = [0u8; 14];
    jump_back[0] = 0xFF;
    jump_back[1] = 0x25;
    jump_back[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let return_addr = (target as u64) + 14;
    jump_back[6..14].copy_from_slice(&return_addr.to_le_bytes());

    std::ptr::copy_nonoverlapping(jump_back.as_ptr(), (trampoline as *mut u8).offset(14), 14);

    VirtualProtect(
        target as *mut winapi::ctypes::c_void,
        14,
        old_protect,
        &mut old_protect,
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

    Ok(trampoline as *mut std::os::raw::c_void)
}
