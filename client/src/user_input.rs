use bishop::{BishopArt, DrawingOptions};
use std::io::{stdout, Write};
use sha1::{Digest, Sha1};
use colored::*;

pub fn verify_key_fingerprint(key: &[u8]) -> bool {
    // compute fingerprint
    let mut hasher = Sha1::new();
    hasher.update(key);

    let fingerprint = hex::encode_upper(hasher.finalize())
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i != 0 && i % 2 == 0 {
                Some(' ')
            } else {
                None
            }
            .into_iter()
            .chain(std::iter::once(c))
        })
        .collect::<String>();

    let randomart = BishopArt::new()
        .chain(key)
        .draw_with_opts(&DrawingOptions {
            top_text: "X25519".to_string(),
            ..Default::default()
        })
        .replace("\n", "\n    ");

    println!(
        "Fingerprint of remote public key:\n\n    {}\n\nRandomart of remote public key:\n\n    {}",
        fingerprint, randomart
    );

    println!(
        "{} Please verify that these details match the actual remote public\n         \
                  key as it will be used to ensure the identity of the server\n         \
                  in the future.\n",
        "WARNING:".bright_yellow()
    );

    print!("Is this correct? <y/N>: ");
    stdout().flush().unwrap_or(());

    let mut decision = String::new();
    std::io::stdin().read_line(&mut decision).unwrap();

    if decision.to_lowercase() == "y\n" {
        return true;
    } else {
        return false;
    }
}