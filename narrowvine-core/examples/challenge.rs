//! Offline smoke test: initialize the CDM and generate a Widevine license
//! request from a synthetic PSSH. No license server needed.
//!
//! cargo run --manifest-path narrowvine-core/Cargo.toml --example challenge \
//!     --no-default-features -- vendor/libwidevinecdm.so

use narrowvine_core::*;

fn widevine_pssh(key_id: &[u8; 16], content_id: &[u8; 16]) -> Vec<u8> {
    let system_id: [u8; 16] = [
        0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21,
        0xed,
    ];
    // WidevinePsshData protobuf: content_id = 1, key_id = 2.
    let mut data = Vec::new();
    data.extend_from_slice(&[0x0a, 16]);
    data.extend_from_slice(content_id);
    data.extend_from_slice(&[0x12, 16]);
    data.extend_from_slice(key_id);

    let total = 4 + 4 + 4 + 16 + 4 + 16 + 4 + data.len();
    let mut pssh = Vec::with_capacity(total);
    pssh.extend_from_slice(&(total as u32).to_be_bytes());
    pssh.extend_from_slice(b"pssh");
    pssh.extend_from_slice(&1u32.to_be_bytes()); // version 1, flags 0
    pssh.extend_from_slice(&system_id);
    pssh.extend_from_slice(&1u32.to_be_bytes()); // one key id
    pssh.extend_from_slice(key_id);
    pssh.extend_from_slice(&(data.len() as u32).to_be_bytes());
    pssh.extend_from_slice(&data);
    pssh
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vendor/libwidevinecdm.so".to_string());

    println!("cdm version: {}", cdm_version(&path).unwrap());
    let mut cdm = Cdm::new(&path, true).expect("load CDM");
    println!("initialized: {}", cdm.initialized());

    let key_id = [0x10u8; 16];
    let content_id = [0x40u8; 16];
    let pssh = widevine_pssh(&key_id, &content_id);

    let r = cdm.create_session_and_generate_request(&pssh, INIT_DATA_CENC, SESSION_TEMPORARY);
    match &r.promise {
        Some(PromiseResult::Session { session_id, .. }) => {
            println!("session id: {:?}", session_id);
        }
        Some(PromiseResult::Rejected {
            exception,
            system_code,
            ..
        }) => println!("rejected: exception={exception} system_code={system_code}"),
        _ => println!("no promise resolved"),
    }
    for m in &r.messages {
        println!(
            "message: type={} len={} head={:02x?}",
            m.message_type,
            m.message.len(),
            &m.message[..m.message.len().min(16)]
        );
    }

    let d = cdm.decrypt(
        b"0123456789abcdef",
        &[],
        &[],
        &[],
        ENCRYPTION_UNENCRYPTED,
        Pattern::default(),
        12345,
    );
    println!(
        "decrypt(unencrypted): status={} data={:?} ts={}",
        status_name(d.status),
        d.data.as_deref().map(String::from_utf8_lossy),
        d.timestamp
    );
}
