pub type RegisterNativesFn = unsafe extern "C" fn(
    env: *mut JniEnv,
    class: JClass,
    methods: *const JniNativeMethod,
    count: JInt,
) -> JInt;

#[repr(C)]
pub struct JniNativeMethod {
    pub name: *const std::os::raw::c_char,
    pub signature: *const std::os::raw::c_char,
    pub function: *mut std::os::raw::c_void,
}

#[repr(C)]
pub struct JniEnv {
    pub functions: *const *const std::os::raw::c_void,
}

#[repr(C)]
pub struct JavaVm {
    pub functions: *const *const std::os::raw::c_void,
}

pub type JClass = *mut std::os::raw::c_void;
pub type JString = *mut std::os::raw::c_void;
pub type JObject = *mut std::os::raw::c_void;
pub type JMethodId = *mut std::os::raw::c_void;
pub type JInt = i32;
