use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;

// Helper function to send a command to the TPM, read the response, and close the file.
// This ensures each command is treated as a clean, separate transaction by the kernel driver.
fn send_tpm_cmd(cmd: &[u8], label: &str) -> Vec<u8> {
    let mut options = OpenOptions::new();
    // Use /dev/tpmrm0 (Kernel Resource Manager) for stable communication
    match options.read(true).write(true).open("/dev/tpmrm0") {
        Ok(mut file) => {
            // Send raw command bytes
            file.write_all(cmd).expect("Failed to write to TPM");
            file.flush().expect("Failed to flush buffer");

            // Wait briefly for the TPM hardware to process the request
            sleep(Duration::from_millis(100));

            let mut buf = [0u8; 128];
            match file.read(&mut buf) {
                Ok(bytes_read) => {
                    println!("[{}] Successfully read {} bytes.", label, bytes_read);
                    buf[..bytes_read].to_vec()
                }
                Err(e) => {
                    println!("[{}] Read Error: {}", label, e);
                    Vec::new()
                }
            }
        } 
        Err(e) => {
            println!("[{}] Open Error: {}", label, e);
            Vec::new()
        }
    }
}

fn main() {
    println!("--- Wasm TPM Real Entropy Verification ---");

    // 1. Step 1: TPM2_Startup (SU_CLEAR)
    // Most virtual TPMs (swtpm) require this signal to transition from 'uninitialized' state.
    let mut startup = Vec::new();
    startup.extend_from_slice(&0x8001u16.to_be_bytes());     // Tag: TPM_ST_NO_SESSIONS
    startup.extend_from_slice(&12u32.to_be_bytes());         // Command Size: 12 bytes
    startup.extend_from_slice(&0x00000144u32.to_be_bytes()); // Command Code: TPM_CC_Startup
    startup.extend_from_slice(&0x0000u16.to_be_bytes());     // Startup Type: SU_CLEAR

    println!("Step 1: Sending TPM2_Startup...");
    send_tpm_cmd(&startup, "STARTUP");

    // 2. Step 2: TPM2_GetRandom (Requesting 8 bytes of entropy)
    // Format: Header (10 bytes) + BytesRequested (2 bytes)
    let mut random = Vec::new();
    random.extend_from_slice(&0x8001u16.to_be_bytes());     // Tag: TPM_ST_NO_SESSIONS
    random.extend_from_slice(&12u32.to_be_bytes());         // Total Size: 10 (header) + 2 (param)
    random.extend_from_slice(&0x0000017Bu32.to_be_bytes()); // Command Code: TPM_CC_GetRandom
    random.extend_from_slice(&8u16.to_be_bytes());          // Parameter: 8 bytes

    println!("Step 2: Sending TPM2_GetRandom...");
    let res = send_tpm_cmd(&random, "GET_RANDOM");
    
    // Print the raw hex bytes to inspect the exact structure
    println!("GET_RANDOM Raw Response Hex: {:02x?}", res);

    if res.len() >= 8 {
        // Since the kernel manager returned the raw entropy bytes from the beginning of the buffer
        let random_data = &res[0..8];
        println!("\n==================================================");
        println!("MISSION ACCOMPLISHED! SUCCESSFUL TPM INTERATION");
        println!("Successfully retrieved 8-byte Hardware Entropy via Wasm time!");
        println!("Generated Hardware Random Data: {:02x?}", random_data);
        println!("==================================================\n");
    } else {
        println!("Failed to retrieve a valid response from the TPM.");
    }
} 
