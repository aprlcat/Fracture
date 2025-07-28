use std::{ffi::CStr, ptr, sync::Mutex, thread, time::Duration};

use anyhow::Result;
use libloading::{Library, Symbol};

use super::*;
use crate::util::{logger, trampoline};

static ORIGINAL: Mutex<Option<RegisterNativesFn>> = Mutex::new(None);

pub fn start() -> Result<()> {
    unsafe {
        let lib = wait_for_jvm()?;
        let vm = get_vm(&lib)?;
        let env = attach(vm)?;
        hook(env)?;

        logger::success("RegisterNatives hook placed");
        Ok(())
    }
}

unsafe fn wait_for_jvm() -> Result<Library> {
    let jvm_paths = [
        "/System/Library/Frameworks/JavaVM.framework/Versions/Current/Libraries/libjvm.dylib",
        "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Home/lib/server/libjvm.dylib",
        "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/server/libjvm.dylib",
    ];

    loop {
        if let Ok(lib) = Library::new("libjvm.dylib") {
            logger::info("Found already loaded libjvm.dylib");
            return Ok(lib);
        }

        for path in &jvm_paths {
            if let Ok(lib) = Library::new(path) {
                logger::info(&format!("Found JVM at {}", path));
                return Ok(lib);
            }
        }

        thread::sleep(Duration::from_millis(50));
    }
}

unsafe fn get_vm(lib: &Library) -> Result<*mut JavaVm> {
    let get_created_vms: Symbol<unsafe extern "C" fn(*mut *mut JavaVm, JInt, *mut JInt) -> JInt> =
        lib.get(b"JNI_GetCreatedJavaVMs\0")?;

    let mut vm: *mut JavaVm = ptr::null_mut();
    let mut count: JInt = 0;

    if get_created_vms(&mut vm, 1, &mut count) != 0 || count == 0 {
        return Err(anyhow::anyhow!("Could not get JavaVM pointer"));
    }

    logger::info(&format!("Got JavaVM at {:p}", vm));
    Ok(vm)
}

unsafe fn attach(vm: *mut JavaVm) -> Result<*mut JniEnv> {
    let attach_fn: unsafe extern "C" fn(
        *mut JavaVm,
        *mut *mut JniEnv,
        *mut std::os::raw::c_void,
    ) -> JInt = std::mem::transmute(*(*vm).functions.offset(4) as *const std::os::raw::c_void);

    let mut env: *mut JniEnv = ptr::null_mut();

    if attach_fn(vm, &mut env, ptr::null_mut()) != 0 {
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

unsafe extern "C" fn hooked(
    env: *mut JniEnv,
    class: JClass,
    methods: *const JniNativeMethod,
    count: JInt,
) -> JInt {
    let classname = get_class_name(env, class).unwrap_or_else(|| "Unknown".to_string());

    logger::hook(&format!(
        "Class '{}' registering {} native methods",
        classname, count
    ));

    for i in 0..count {
        let method = &*methods.offset(i as isize);
        let name = CStr::from_ptr(method.name).to_string_lossy();
        let signature = CStr::from_ptr(method.signature).to_string_lossy();
        let (module, offset) = get_module_info(method.function);
        let readable = parse_signature(&signature, &name);

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

unsafe fn get_class_name(env: *mut JniEnv, class: JClass) -> Option<String> {
    if class.is_null() {
        return None;
    }

    let find_class: unsafe extern "C" fn(*mut JniEnv, *const i8) -> JClass =
        std::mem::transmute(*(*env).functions.offset(6) as *const std::os::raw::c_void);

    let get_method_id: unsafe extern "C" fn(
        *mut JniEnv,
        JClass,
        *const i8,
        *const i8,
    ) -> JMethodId =
        std::mem::transmute(*(*env).functions.offset(33) as *const std::os::raw::c_void);

    let call_object_method: unsafe extern "C" fn(*mut JniEnv, JObject, JMethodId) -> JObject =
        std::mem::transmute(*(*env).functions.offset(36) as *const std::os::raw::c_void);

    let get_string_utf_chars: unsafe extern "C" fn(*mut JniEnv, JString, *mut u8) -> *const i8 =
        std::mem::transmute(*(*env).functions.offset(169) as *const std::os::raw::c_void);

    let release_string_utf_chars: unsafe extern "C" fn(*mut JniEnv, JString, *const i8) =
        std::mem::transmute(*(*env).functions.offset(170) as *const std::os::raw::c_void);

    let class_class = find_class(env, b"java/lang/Class\0".as_ptr() as *const i8);
    if class_class.is_null() {
        return None;
    }

    let method = get_method_id(
        env,
        class_class,
        b"getName\0".as_ptr() as *const i8,
        b"()Ljava/lang/String;\0".as_ptr() as *const i8,
    );

    if method.is_null() {
        return None;
    }

    let name_string = call_object_method(env, class, method);
    if name_string.is_null() {
        return None;
    }

    let utf_name = get_string_utf_chars(env, name_string, ptr::null_mut());
    if utf_name.is_null() {
        return None;
    }

    let result = CStr::from_ptr(utf_name).to_string_lossy().to_string();
    release_string_utf_chars(env, name_string, utf_name);

    Some(result)
}

fn get_module_info(address: *mut std::os::raw::c_void) -> (String, usize) {
    unsafe {
        use std::ffi::CStr;

        use mach2::dyld::{_dyld_get_image_header, _dyld_get_image_name, _dyld_image_count};

        let addr = address as usize;
        let image_count = _dyld_image_count();

        for i in 0..image_count {
            let header = _dyld_get_image_header(i);
            if header.is_null() {
                continue;
            }

            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }

            let base_addr = header as usize;

            // actually parse mach-o header later
            if addr >= base_addr && addr < base_addr + 0x100000 {
                let name = CStr::from_ptr(name_ptr).to_string_lossy();
                let module_name = std::path::Path::new(&*name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown")
                    .to_string();

                let offset = addr - base_addr;
                return (module_name, offset);
            }
        }

        ("Unknown".to_string(), 0)
    }
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
            let base_type = parse_type_chars(chars);
            format!("{}[]", base_type)
        }
        _ => "unknown".to_string(),
    }
}
