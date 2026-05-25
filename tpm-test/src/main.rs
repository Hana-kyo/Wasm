use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::thread::sleep;
use std::time::Duration;
use std::mem::size_of;

// =============================================================================
// TPM 2.0 Base Framework (Headers & Session)
// =============================================================================

#[repr(C, packed)]
struct TpmCmdHeader {
    tag: u16,
    size: u32,
    command_code: u32,
}

#[repr(C, packed)]
struct TpmRspHeader {
    tag: u16,
    size: u32,
    return_code: u32,
}

// Every TPM command structure must implement this trait
trait TpmCommand {
    fn as_raw_bytes(&self) -> &[u8];
    fn delay_ms(&self) -> u64 { 100 }
    fn command_name(&self) -> &str;
}

// Session manager that holds the active file descriptor
struct TpmSession {
    file: std::fs::File,
}

impl TpmSession {
    fn open(path: &str) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(TpmSession { file })
    }

    // Generic execution pipeline
    fn execute<C: TpmCommand>(&mut self, cmd: &C) -> u32 {
        println!("--> Dispatching: {}", cmd.command_name());
        self.file.write_all(cmd.as_raw_bytes()).unwrap();
        self.file.flush().unwrap();
        
        sleep(Duration::from_millis(cmd.delay_ms()));

        let mut buf = [0u8; 1024];
        let read_bytes = self.file.read(&mut buf).unwrap();

        if read_bytes >= 10 {
            let rsp_header = unsafe { &*(buf.as_ptr() as *const TpmRspHeader) };
            u32::from_be(rsp_header.return_code)
        } else {
            0xFFFFFFFF
        }
    }
}

// =============================================================================
// Command 1: TPM2_CreatePrimary Layout
// =============================================================================

#[repr(C, packed)]
struct u24_dummy { bytes: [u8; 3] }

#[repr(C, packed)]
struct CreatePrimaryPayload {
    header: TpmCmdHeader,
    primary_handle: u32,
    in_sensitive_size: u16,
    user_auth_size: u16,
    in_sensitive_data_size: u16,
    in_public_size: u16,
    type_alg: u16,
    name_alg: u16,
    object_attributes: u32,
    auth_policy_size: u16,
    sym_alg: u16,
    sym_key_bits: u16,
    sym_mode: u16,
    scheme: u16,
    rsa_modulus_bits: u16,
    rsa_exponent: u32,
    unique_size: u16,
    outside_info_size: u16,
    pcr_selection_size: u32,
    pcr_hash_alg: u16,
    pcr_size_of_select: u8,
    pcr_select_bitmap: u24_dummy,
}

impl CreatePrimaryPayload {
    fn new() -> Self {
        let total_size = size_of::<Self>() as u32;
        CreatePrimaryPayload {
            header: TpmCmdHeader {
                tag: 0x8001u16.to_be(),
                size: total_size.to_be(),
                command_code: 0x00000131u32.to_be(), // TPM_CC_CreatePrimary
            },
            primary_handle: 0x40000001u32.to_be(),
            in_sensitive_size: 4u16.to_be(),
            user_auth_size: 0u16.to_be(),
            in_sensitive_data_size: 0u16.to_be(),
            in_public_size: 52u16.to_be(),
            type_alg: 0x0001u16.to_be(),
            name_alg: 0x000Bu16.to_be(),
            object_attributes: 0x0004004Au32.to_be(),
            auth_policy_size: 0u16.to_be(),
            sym_alg: 0x0006u16.to_be(),
            sym_key_bits: 128u16.to_be(),
            sym_mode: 0x0003u16.to_be(),
            scheme: 0x0010u16.to_be(),
            rsa_modulus_bits: 2048u16.to_be(),
            rsa_exponent: 0u32.to_be(),
            unique_size: 0u16.to_be(),
            outside_info_size: 0u16.to_be(),
            pcr_selection_size: 1u32.to_be(),
            pcr_hash_alg: 0x000Bu16.to_be(),
            pcr_size_of_select: 3,
            pcr_select_bitmap: u24_dummy { bytes: [0x00, 0x00, 0x00] },
        }
    }
}

impl TpmCommand for CreatePrimaryPayload {
    fn as_raw_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
    fn delay_ms(&self) -> u64 { 1000 } // Long execution for RSA generation
    fn command_name(&self) -> &str { "TPM2_CreatePrimary (RSA 2048 SRK)" }
}

// =============================================================================
// Command 2: TPM2_GetRandom Layout (NEW)
// =============================================================================

#[repr(C, packed)]
struct GetRandomPayload {
    header: TpmCmdHeader,
    bytes_requested: u16,
}

impl GetRandomPayload {
    fn new(bytes: u16) -> Self {
        let total_size = size_of::<Self>() as u32;
        GetRandomPayload {
            header: TpmCmdHeader {
                tag: 0x8001u16.to_be(),
                size: total_size.to_be(),
                command_code: 0x0000017Bu32.to_be(), // TPM_CC_GetRandom
            },
            bytes_requested: bytes.to_be(),
        }
    }
}

impl TpmCommand for GetRandomPayload {
    fn as_raw_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const Self as *const u8, size_of::<Self>()) }
    }
    fn delay_ms(&self) -> u64 { 100 }
    fn command_name(&self) -> &str { "TPM2_GetRandom (Hardware Entropy Request)" }
}

// =============================================================================
// Main Sequential Execution Pipeline
// =============================================================================
fn main() {
    println!("--- Multi-Command Sequential Session ---");

    match TpmSession::open("/dev/tpmrm0") {
        Ok(mut session) => {
            // 1. First Command: Create Permanent Root Key Context
            let cmd_primary = CreatePrimaryPayload::new();
            let rc1 = session.execute(&cmd_primary);
            println!("   -> Return Code: 0x{:08X}", rc1);

            println!("--------------------------------------------------");

            // 2. Second Command: Pull dynamic high-entropy bytes from TPM within the SAME pipe
            let cmd_random = GetRandomPayload::new(8);
            let rc2 = session.execute(&cmd_random);
            println!("   -> Return Code: 0x{:08X}", rc2);

            println!("\n==================================================");
            if rc1 == 0 && rc2 == 0 {
                println!("MULTI-COMMAND PIPELINE COMPLETELY SUCCESSFUL!");
                println!("Both Root Key generation and Entropy injection verified in one session loop.");
            } else {
                println!("Pipeline failure detected during sequential sequence execution.");
            }
            println!("==================================================");
        }
        Err(e) => println!("Failed to initialize secure session context: {}", e),
    }
}
