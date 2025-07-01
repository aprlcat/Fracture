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

static ORIGINAL: Mutex<Option<RegisterNativesFn>> = Mutex::new(None);

pub fn start() -> Result<()> {
    unsafe {
        let module = waitjvm()?;
        let vm = getvm(module)?;
        let env = attach(vm)?;
        hook(env)?;

        logger::success("RegisterNatives hook placed");
        Ok(())
    }
}

unsafe fn waitjvm() -> Result<HMODULE> {
    let mut module: HMODULE = std::ptr::null_mut();

    while module.is_null() {
        module = GetModuleHandleA(b"jvm.dll\0".as_ptr() as *const i8);
        Sleep(50);
    }

    logger::info(&format!("Found jvm.dll at {:p}", module));
    Ok(module)
}

unsafe fn getvm(module: HMODULE) -> Result<*mut JavaVm> {
    let getvms = GetProcAddress(module, b"JNI_GetCreatedJavaVMs\0".as_ptr() as *const i8);

    if getvms.is_null() {
        return Err(anyhow::anyhow!("Could not find JNI_GetCreatedJavaVMs"));
    }

    let getvms: extern "system" fn(*mut *mut JavaVm, JInt, *mut JInt) -> JInt =
        std::mem::transmute(getvms);

    let mut vm: *mut JavaVm = std::ptr::null_mut();
    let mut count: JInt = 0;

    if getvms(&mut vm, 1, &mut count) != 0 || count == 0 {
        return Err(anyhow::anyhow!("Could not get JavaVM pointer"));
    }

    Ok(vm)
}

unsafe fn attach(vm: *mut JavaVm) -> Result<*mut JniEnv> {
    let attach: extern "system" fn(
        *mut JavaVm,
        *mut *mut JniEnv,
        *mut std::os::raw::c_void,
    ) -> JInt = std::mem::transmute(*(*vm).functions.offset(4) as *const std::os::raw::c_void);

    let mut env: *mut JniEnv = std::ptr::null_mut();

    if attach(vm, &mut env, std::ptr::null_mut()) != 0 {
        return Err(anyhow::anyhow!("Could not attach to thread"));
    }

    logger::info(&format!("Attached to thread, JNIEnv: {:p}", env));
    Ok(env)
}

unsafe fn hook(env: *mut JniEnv) -> Result<()> {
    let vtable = (*env).functions as *mut *mut std::os::raw::c_void;
    let target = vtable.offset(REGISTER_NATIVES_INDEX as isize);

    let original = trampoline::place(*target, hooked as *mut std::os::raw::c_void)?;
    *ORIGINAL.lock().unwrap() = Some(std::mem::transmute(original));

    Ok(())
}

unsafe extern "system" fn hooked(
    env: *mut JniEnv,
    class: JClass,
    methods: *const JniNativeMethod,
    count: JInt,
) -> JInt {
    let classname = getclass(env, class).unwrap_or_else(|| "Unknown".to_string());

    logger::hook(&format!("Class '{}' registering {} native methods", classname, count));

    for i in 0..count {
        let method = &*methods.offset(i as isize);
        let name = CStr::from_ptr(method.name).to_string_lossy();
        let signature = CStr::from_ptr(method.signature).to_string_lossy();
        let (module, offset) = getmodule(method.function);
        let readable = parsesig(&signature, &name);

        let info = format!(
            "  {} | {} | 0x{:X} | 0x{:016X}",
            readable, module, offset, method.function as usize
        );

        logger::method(&info);
    }

    let original = ORIGINAL.lock().unwrap();
    if let Some(func) = *original {
        func(env, class, methods, count)
    } else {
        -1
    }
}

unsafe fn getclass(env: *mut JniEnv, class: JClass) -> Option<String> {
    if class.is_null() {
        return None;
    }

    let findclass: extern "system" fn(*mut JniEnv, *const i8) -> JClass =
        std::mem::transmute(*(*env).functions.offset(6) as *const std::os::raw::c_void);

    let getmethod: extern "system" fn(*mut JniEnv, JClass, *const i8, *const i8) -> JMethodId =
        std::mem::transmute(*(*env).functions.offset(33) as *const std::os::raw::c_void);

    let callmethod: extern "system" fn(*mut JniEnv, JObject, JMethodId) -> JObject =
        std::mem::transmute(*(*env).functions.offset(36) as *const std::os::raw::c_void);

    let getstring: extern "system" fn(*mut JniEnv, JString, *mut u8) -> *const i8 =
        std::mem::transmute(*(*env).functions.offset(169) as *const std::os::raw::c_void);

    let releasestring: extern "system" fn(*mut JniEnv, JString, *const i8) =
        std::mem::transmute(*(*env).functions.offset(170) as *const std::os::raw::c_void);

    let classclass = findclass(env, b"java/lang/Class\0".as_ptr() as *const i8);
    if classclass.is_null() {
        return None;
    }

    let method = getmethod(
        env,
        classclass,
        b"getName\0".as_ptr() as *const i8,
        b"()Ljava/lang/String;\0".as_ptr() as *const i8,
    );

    if method.is_null() {
        return None;
    }

    let namestring = callmethod(env, class, method);
    if namestring.is_null() {
        return None;
    }

    let utfname = getstring(env, namestring, std::ptr::null_mut());
    if utfname.is_null() {
        return None;
    }

    let result = CStr::from_ptr(utfname).to_string_lossy().to_string();
    releasestring(env, namestring, utfname);

    Some(result)
}

fn getmodule(address: *mut std::os::raw::c_void) -> (String, usize) {
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
                let pathstr = CStr::from_ptr(path.as_ptr()).to_string_lossy().to_string();
                let modulename = std::path::Path::new(&pathstr)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("Unknown")
                    .to_string();

                let offset = address as usize - module as usize;
                return (modulename, offset);
            }
        }

        ("Unknown".to_string(), 0)
    }
}

fn parsesig(signature: &str, name: &str) -> String {
    let mut result = String::new();

    let returnstart = signature.find(')').map(|i| i + 1).unwrap_or(0);
    let returntype = parsetype(&signature[returnstart..]);

    result.push_str(&returntype);
    result.push(' ');
    result.push_str(name);
    result.push('(');

    let paramstart = signature.find('(').map(|i| i + 1).unwrap_or(0);
    let paramend = signature.find(')').unwrap_or(signature.len());
    let params = &signature[paramstart..paramend];

    let mut chars = params.chars().peekable();
    let mut first = true;

    while chars.peek().is_some() {
        if !first {
            result.push_str(", ");
        }
        first = false;

        let paramtype = parsetypechars(&mut chars);
        result.push_str(&paramtype);
    }

    result.push(')');
    result
}

fn parsetype(sig: &str) -> String {
    let mut chars = sig.chars().peekable();
    parsetypechars(&mut chars)
}

fn parsetypechars(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
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
            let mut classname = String::new();
            while let Some(ch) = chars.next() {
                if ch == ';' {
                    break;
                }
                classname.push(if ch == '/' { '.' } else { ch });
            }
            classname
        }
        Some('[') => {
            let basetype = parsetypechars(chars);
            format!("{}[]", basetype)
        }
        _ => "unknown".to_string(),
    }
}