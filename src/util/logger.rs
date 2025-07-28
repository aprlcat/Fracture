use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

static LOG_FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn init() {
    if let Some(path) = create_log_path() {
        if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
            *LOG_FILE.lock().unwrap() = Some(file);
            success(&format!("Log file created at: {}", path.display()));
            write("[+] Fracture logging initialized");
        } else {
            eprintln!("Failed to create log file at: {}", path.display());
        }
    } else {
        eprintln!("Failed to determine log path");
    }
}

fn create_log_path() -> Option<PathBuf> {
    let mut path = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    path.push("fracture");
    path.push("logs");

    if std::fs::create_dir_all(&path).is_ok() {
        path.push("fracture.log");
        Some(path)
    } else {
        None
    }
}

pub fn write(message: &str) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let log_message = format!("[{}] {}\n", timestamp, message);

    if let Ok(mut guard) = LOG_FILE.lock() {
        if let Some(ref mut file) = *guard {
            let _ = file.write_all(log_message.as_bytes());
            let _ = file.flush();
        }
    }
}

pub fn success(message: &str) {
    let msg = format!("[+] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn error(message: &str) {
    let msg = format!("[!] {}", message);
    eprintln!("{}", msg);
    write(&msg);
}

pub fn info(message: &str) {
    let msg = format!("[?] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn hook(message: &str) {
    let msg = format!("[→] {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn method(message: &str) {
    let msg = format!("    {}", message);
    println!("{}", msg);
    write(&msg);
}

pub fn debug(message: &str) {
    let msg = format!("[*] {}", message);
    println!("{}", msg);
    write(&msg);
}
