use std::ptr;

use anyhow::Result;
use mach2::{
    kern_return::KERN_SUCCESS,
    vm::{mach_vm_allocate, mach_vm_protect},
    vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE},
};

use crate::util::logger;

extern "C" {
    fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
}

extern "C" {
    fn mach_task_self() -> mach2::port::mach_port_t;
}

pub unsafe fn place(
    target: *mut std::os::raw::c_void,
    hook: *mut std::os::raw::c_void,
) -> Result<*mut std::os::raw::c_void> {
    if target.is_null() || hook.is_null() {
        return Err(anyhow::anyhow!("Null pointer provided"));
    }

    if mach_vm_protect(
        mach_task_self(),
        target as u64,
        14,
        0,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    ) != KERN_SUCCESS
    {
        return Err(anyhow::anyhow!("Failed to change memory protection"));
    }

    // save orig
    let mut original = [0u8; 14];
    ptr::copy_nonoverlapping(target as *const u8, original.as_mut_ptr(), 14);
    let mut jump = [0u8; 14];
    jump[0] = 0xFF; // JMP
    jump[1] = 0x25; // [RIP+0]
    jump[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // offset

    let hook_addr = hook as u64;
    jump[6..14].copy_from_slice(&hook_addr.to_le_bytes());
    ptr::copy_nonoverlapping(jump.as_ptr(), target as *mut u8, 14);
    let mut trampoline_addr: u64 = 0;
    if mach_vm_allocate(mach_task_self(), &mut trampoline_addr, 28, 1) != KERN_SUCCESS {
        // restore
        ptr::copy_nonoverlapping(original.as_ptr(), target as *mut u8, 14);
        return Err(anyhow::anyhow!("Failed to allocate trampoline"));
    }

    let trampoline = trampoline_addr as *mut u8;

    if mach_vm_protect(
        mach_task_self(),
        trampoline_addr,
        28,
        0,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
    ) != KERN_SUCCESS
    {
        return Err(anyhow::anyhow!("Failed to make trampoline executable"));
    }

    ptr::copy_nonoverlapping(original.as_ptr(), trampoline, 14);

    let mut jump_back = [0u8; 14];
    jump_back[0] = 0xFF;
    jump_back[1] = 0x25;
    jump_back[2..6].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let return_addr = (target as u64) + 14;
    jump_back[6..14].copy_from_slice(&return_addr.to_le_bytes());

    ptr::copy_nonoverlapping(jump_back.as_ptr(), trampoline.offset(14), 14);

    sys_icache_invalidate(target as *mut libc::c_void, 14);
    sys_icache_invalidate(trampoline as *mut libc::c_void, 28);

    logger::debug(&format!(
        "Trampoline: Target=0x{:016X}, Hook=0x{:016X}, Trampoline=0x{:016X}",
        target as usize, hook as usize, trampoline as usize
    ));

    Ok(trampoline as *mut std::os::raw::c_void)
}
