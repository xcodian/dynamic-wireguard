use bishop::{BishopArt, DrawingOptions};
use sha1::{Digest, Sha1};
use colored::*;

pub fn print_fingerprint(public_key: &[u8]) {
    // compute fingerprint
    let mut hasher = Sha1::new();
    hasher.update(public_key);

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
        .chain(public_key)
        .draw_with_opts(&DrawingOptions {
            top_text: "X25519".to_string(),
            ..Default::default()
        })
        .replace("\n", "\n    ");

    println!(
        "Fingerprint of public key:\n\n    {}\n\nRandomart of public key:\n\n    {}",
        fingerprint, randomart
    );

    println!(
        "{} You should distribute these to clients in order to allow them to\n      \
               verify this server's authenticity.\n",
        "NOTE:".bright_yellow()
    );
}