use std::fs::File;
use std::io::Read;

fn main() {
    println!("--- Wasm TPM Access Test ---");

    //Open the TPM devide mapped via WASI
    match File::open("/dev/tpm0"){
        Ok(mut file) => {
            let mut buffer = [0u8; 8];
            if file.read_exact(&mut buffer).is_ok() {
                println!("Success！Random data from TPM:{:02x?}", buffer);
            } else {
                println!("Error:Failed to read data from the device.");
            }
        }
        Err(e) => {
            println!("Error:Could not open /dev/tpm0.");
            println!("Reason:{}",e);
            println!("Hint:Check if '--dir /dev::/dev' is used and if you have sudo privileges.");
        }
    }
}
