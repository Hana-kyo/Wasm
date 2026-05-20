use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;

// TPMにコマンドを送り、レスポンスをきっちり読み切ってファイルを閉じる関数
fn send_tpm_cmd(cmd: &[u8], label: &str) -> Vec<u8> {
    let mut options = OpenOptions::new();
    match options.read(true).write(true).open("/dev/tpmrm0") {
        Ok(mut file) => {
            // コマンド送信
            if let Err(e) = file.write_all(cmd) {
                println!("[{}] Write Error: {}", label, e);
                return Vec::new();
            }
            let _ = file.flush();

            // ドライバが処理を終えるまで極小のウェイトを入れる
            sleep(Duration::from_millis(50));

            // レスポンスを読み切る
            let mut buf = [0u8; 64];
            match file.read(&mut buf) {
                Ok(bytes_read) => {
                    println!("[{}] Read {} bytes.", label, bytes_read);
                    buf[..bytes_read].to_vec()
                }
                Err(e) => {
                    println!("[{}] Read Error: {}", label, e);
                    Vec::new()
                }
            }
        } // ここで file がスコープを抜け、デバイスファイルが「完全に閉じられる」
        Err(e) => {
            println!("[{}] Open Error: {}", label, e);
            Vec::new()
        }
    }
}

fn main() {
    println!("--- Wasm TPM Strict Transaction Test ---");

    // 1. TPM2_Startup 命令 (12 bytes)
    let startup_cmd: [u8; 12] = [
        0x00, 0x80, 0x00, 0x00, 0x00, 0x0C, 
        0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    println!("Executing Step 1: Startup...");
    let startup_res = send_tpm_cmd(&startup_cmd, "STARTUP");
    println!("Startup Raw Hex: {:02x?}\n", startup_res);

    // 2. TPM2_GetRandom 命令 (14 bytes)
    let random_cmd: [u8; 14] = [
        0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 
        0x00, 0x00, 0x01, 0x7B, 0x00, 0x02, 0x00, 0x08,
    ];
    println!("Executing Step 2: GetRandom...");
    let random_res = send_tpm_cmd(&random_cmd, "GET_RANDOM");
    
    if random_res.len() >= 10 {
        let rc = ((random_res[6] as u32) << 24) |
                 ((random_res[7] as u32) << 16) |
                 ((random_res[8] as u32) << 8)  |
                 (random_res[9] as u32);
        println!("TPM Response Code: 0x{:08X}", rc);

        if rc == 0 && random_res.len() >= 22 {
            let random_data = &random_res[random_res.len() - 8..];
            println!("SUCCESS! TPM Random Data: {:02x?}", random_data);
        } else if rc == 0x100 {
            println!("Hint: TPM requires initialization (TPM_RC_INITIALIZE). Startup was necessary.");
        }
    } else {
        println!("Failed to get valid length response.");
    }
}
