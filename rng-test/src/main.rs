use std::fs::File;
use std::io::Read;

fn main() {
    println!("--- Wasm OS-RNG Access Test ---");
    
    // Open the OS random number generator
    match File::open("/dev/urandom") {
        Ok(mut file) => {
            let mut buffer = [0u8; 8];
            if file.read_exact(&mut buffer).is_ok() {
                println!("Success! Random data from OS: {:02x?}", buffer);
            } else {
                println!("Error: Failed to read from /dev/urandom.");
            }
        }
        Err(e) => {
            println!("Error: Could not open /dev/urandom.");
            println!("Reason: {}", e);
        }
    }
}
