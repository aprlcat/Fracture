#![allow(unsafe_op_in_unsafe_fn)]

mod jvm;
mod util;

#[no_mangle]
pub extern "C" fn constructor() {
    util::logger::init();

    std::thread::spawn(|| match jvm::hook::start() {
        Ok(_) => {
            util::logger::success("Fracture initialized successfully");
        }
        Err(e) => {
            util::logger::error(&format!("Failed to initialize: {}", e));
        }
    });
}

// mac dylib constructor
#[link_section = "__DATA,__mod_init_func"]
#[used]
static INIT_ARRAY: [extern "C" fn(); 1] = [constructor];
