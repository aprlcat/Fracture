use std::{ffi::CStr, sync::Mutex};

use anyhow::Result;
use winapi::{
    shared::minwindef::HMODULE,
    um::{
        libloaderapi::{GetModuleHandleA, GetProcAddress},
        synchapi::Sleep,
    },
};

use super::*;
use crate::util::{logger, trampoline};

static ORIGINAL_FUNCTION: Mutex<Option<RegisterNativesFn>> = Mutex::new(None);

pub fn start() -> Result<()> {
    unsafe {
        let vm_module = waitfor_jvm()?;
        let java_vm = get_javavm(vm_module)?;
        let env = attach_thread(java_vm)?;
        hook_natives(env)?;

        println!("[+] RegisterNatives hook placed successfully");
        Ok(())
    }
}

unsafe fn waitfor_jvm() -> Result<HMODULE> {
    let mut module: HMODULE = std::ptr::null_mut();

    while module.is_null() {
        module = GetModuleHandleA(b"jvm.dll\0".as_ptr() as *const i8);
        Sleep(50);
    }

    println!("[+] Found jvm.dll at {:p}", module);
    Ok(module)
}

unsafe fn get_javavm(module: HMODULE) -> Result<*mut JavaVm> {
    let get_vms = GetProcAddress(module, b"JNI_GetCreatedJavaVMs\0".as_ptr() as *const i8);

    if get_vms.is_null() {
        return Err(anyhow::anyhow!("Could not find JNI_GetCreatedJavaVMs"));
    }

    let get_vms: extern "system" fn(*mut *mut JavaVm, JInt, *mut JInt) -> JInt =
        std::mem::transmute(get_vms);

    let mut vm: *mut JavaVm = std::ptr::null_mut();
    let mut count: JInt = 0;

    if get_vms(&mut vm, 1, &mut count) != 0 || count == 0 {
        return Err(anyhow::anyhow!("Could not get JavaVM pointer"));
    }

    Ok(vm)
}

unsafe fn attach_thread(vm: *mut JavaVm) -> Result<*mut JniEnv> {
    let attach: extern "system" fn(
        *mut JavaVm,
        *mut *mut JniEnv,
        *mut std::os::raw::c_void,
    ) -> JInt = std::mem::transmute(*(*vm).functions.offset(4) as *const std::os::raw::c_void);

    let mut env: *mut JniEnv = std::ptr::null_mut();

    if attach(vm, &mut env, std::ptr::null_mut()) != 0 {
        return Err(anyhow::anyhow!("Could not attach to thread"));
    }

    println!("[+] Attached to thread, JNIEnv: {:p}", env);
    Ok(env)
}

unsafe fn hook_natives(env: *mut JniEnv) -> Result<()> {
    let vtable = (*env).functions as *mut *mut std::os::raw::c_void;
    let target = vtable.offset(REGISTER_NATIVES_INDEX as isize);

    let original = trampoline::place(*target, hooked as *mut std::os::raw::c_void)?;
    *ORIGINAL_FUNCTION.lock().unwrap() = Some(std::mem::transmute(original));

    Ok(())
}

unsafe extern "system" fn hooked(
    env: *mut JniEnv,
    class: JClass,
    methods: *const JniNativeMethod,
    count: JInt,
) -> JInt {
    let class_name = classname(env, class).unwrap_or_else(|| "Unknown".to_string());

    let header = format!(
        "[+] Class '{}' registering {} native methods",
        class_name, count
    );
    println!("{}", header);
    logger::write(&header);

    for i in 0..count {
        let method = &*methods.offset(i as isize);
        let name = CStr::from_ptr(method.name).to_string_lossy();
        let signature = CStr::from_ptr(method.signature).to_string_lossy();
        let (module_path, offset) = moduleinfo(method.function);
        let readable = parse_signature(&signature, &name);
        let module_name = std::path::Path::new(&module_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Unknown");

        let info = format!(
            "    [→] {} | {} | 0x{:X} | 0x{:016X}",
            readable, module_name, offset, method.function as usize
        );

        println!("{}", info);
        logger::write(&info);
    }

    let original = ORIGINAL_FUNCTION.lock().unwrap();
    if let Some(func) = *original {
        func(env, class, methods, count)
    } else {
        -1
    }
}

fn moduleinfo(address: *mut std::os::raw::c_void) -> (String, usize) {
    unsafe {
        use winapi::um::{
            libloaderapi::{GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleHandleExA},
            processthreadsapi::GetCurrentProcess,
            psapi::GetModuleFileNameExA,
        };

        let mut module = std::ptr::null_mut();

        if GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            address as *const i8,
            &mut module,
        ) != 0
        {
            let mut path = [0i8; 260];
            let result = GetModuleFileNameExA(GetCurrentProcess(), module, path.as_mut_ptr(), 260);

            if result != 0 {
                let path_str = CStr::from_ptr(path.as_ptr()).to_string_lossy().to_string();

                let offset = address as usize - module as usize;
                return (path_str, offset);
            }
        }

        ("Unknown".to_string(), 0)
    }
}

unsafe fn classname(env: *mut JniEnv, class: JClass) -> Option<String> {
    if class.is_null() {
        return None;
    }

    let find_class: extern "system" fn(*mut JniEnv, *const i8) -> JClass =
        std::mem::transmute(*(*env).functions.offset(6) as *const std::os::raw::c_void);

    let get_method: extern "system" fn(*mut JniEnv, JClass, *const i8, *const i8) -> JMethodId =
        std::mem::transmute(*(*env).functions.offset(33) as *const std::os::raw::c_void);

    let call_method: extern "system" fn(*mut JniEnv, JObject, JMethodId) -> JObject =
        std::mem::transmute(*(*env).functions.offset(36) as *const std::os::raw::c_void);

    let get_string: extern "system" fn(*mut JniEnv, JString, *mut u8) -> *const i8 =
        std::mem::transmute(*(*env).functions.offset(169) as *const std::os::raw::c_void);

    let release_string: extern "system" fn(*mut JniEnv, JString, *const i8) =
        std::mem::transmute(*(*env).functions.offset(170) as *const std::os::raw::c_void);

    let class_class = find_class(env, b"java/lang/Class\0".as_ptr() as *const i8);
    if class_class.is_null() {
        return None;
    }

    let method = get_method(
        env,
        class_class,
        b"getName\0".as_ptr() as *const i8,
        b"()Ljava/lang/String;\0".as_ptr() as *const i8,
    );

    if method.is_null() {
        return None;
    }

    let name_string = call_method(env, class, method);
    if name_string.is_null() {
        return None;
    }

    let utf_name = get_string(env, name_string, std::ptr::null_mut());
    if utf_name.is_null() {
        return None;
    }

    let result = CStr::from_ptr(utf_name).to_string_lossy().to_string();
    release_string(env, name_string, utf_name);

    Some(result)
}

fn parse_signature(signature: &str, name: &str) -> String {
    let mut result = String::new();

    let return_start = signature.find(')').map(|i| i + 1).unwrap_or(0);
    let return_type = parse_type(&signature[return_start..]);

    result.push_str(&return_type);
    result.push(' ');
    result.push_str(name);
    result.push('(');

    let param_start = signature.find('(').map(|i| i + 1).unwrap_or(0);
    let param_end = signature.find(')').unwrap_or(signature.len());
    let params = &signature[param_start..param_end];

    let mut chars = params.chars().peekable();
    let mut first = true;

    while chars.peek().is_some() {
        if !first {
            result.push_str(", ");
        }
        first = false;

        let param_type = parse_type_chars(&mut chars);
        result.push_str(&param_type);
    }

    result.push(')');
    result
}

fn parse_type(sig: &str) -> String {
    let mut chars = sig.chars().peekable();
    parse_type_chars(&mut chars)
}

fn parse_type_chars(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    match chars.next() {
        Some('V') => "void".to_string(),
        Some('Z') => "boolean".to_string(),
        Some('B') => "byte".to_string(),
        Some('C') => "char".to_string(),
        Some('S') => "short".to_string(),
        Some('I') => "int".to_string(),
        Some('J') => "long".to_string(),
        Some('F') => "float".to_string(),
        Some('D') => "double".to_string(),
        Some('L') => {
            let mut class_name = String::new();
            while let Some(ch) = chars.next() {
                if ch == ';' {
                    break;
                }
                class_name.push(if ch == '/' { '.' } else { ch });
            }
            class_name
        }
        Some('[') => {
            let base_type = parse_type_chars(chars);
            format!("{}[]", base_type)
        }
        _ => "unknown".to_string(),
    }
}
