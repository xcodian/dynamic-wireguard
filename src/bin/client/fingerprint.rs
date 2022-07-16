use colored::*;
use log::{info, warn};
use sha1::{Digest, Sha1};
use std::{
    fs::OpenOptions,
    io::{self, stdout, BufRead, IoSlice, Write},
};

enum SavedState {
    Match,
    Mismatch,
    NotSaved,
}

fn human_readable_hex(hexstr: &str) -> String {
    return hexstr
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
}

pub fn verify_fingerprint(hostname: &str, public_key: &[u8]) -> bool {
    // compute fingerprint
    let mut hasher = Sha1::new();
    hasher.update(public_key);

    let fingerprint = hex::encode_upper(hasher.finalize());

    match validate_saved(hostname, &fingerprint) {
        SavedState::Match => return true,
        SavedState::Mismatch => return false,
        SavedState::NotSaved => {}
    };

    warn!(
        "The authenticity of host '{}' can't be established.\nFingerprint of remote public key:\n\n    {}\n",
        hostname, human_readable_hex(&fingerprint).bold()
    );

    println!(
        "{} Please verify that this fingerprint matches the remote's actual\n         \
            fingerprint as it will be used to ensure the identity\n         \
            of the server in the future.\n",
        "WARNING:".bright_yellow().bold()
    );

    print!("Is this correct? <y/N>: ");
    if let Err(_) = stdout().flush() {
        return false;
    }

    let mut decision = String::new();
    if let Err(_) = std::io::stdin().read_line(&mut decision) {
        return false;
    }

    if decision.trim().to_lowercase() == "y" {
        save_fingerprint(hostname, &fingerprint);
        return true;
    }

    return false;
}

fn validate_saved(hostname: &str, fingerprint: &str) -> SavedState {
    let file = OpenOptions::new().read(true).open("wgd_known_hosts");

    if let Ok(f) = file {
        // go through each line in the file
        let mut n = 0;

        for line in io::BufReader::new(f).lines() {
            n += 1;

            let line = line.unwrap();

            // split the line into hostname and fingerprint
            let parts: Vec<&str> = line.split(' ').collect();

            if parts.len() != 2 || hex::decode(parts[1]).is_err() || parts[1].len() != 40 {
                warn!("wgd_known_hosts: line {} is invalid", n);
                continue;
            }

            if hostname == parts[0] {
                if fingerprint == parts[1] {
                    info!("Remote identity verified (wgd_known_hosts:{})", n);
                    return SavedState::Match;
                } else {
                    println!(
                        "{} The saved fingerprint does not match the remote's presented\n\
                        fingerprint.\n\
                        \n\
                        {} {}\n\
                        {} {}\n\
                        \n\
                        The address you are connecting to may now point to a different\n\
                        server from the last time you connected, or the server may have\n\
                        been reconfigured with a new keypair.\n\
                        \n\
                        In the worst case, your connection may be being intercepted right now.\n\
                        \n\
                        If you are absolutely sure that the server should be trusted with the\n\
                        new fingerprint, {}.",
                        "SECURITY ERROR:".bright_red().bold(),
                        " SAVED".bright_green().bold(),
                        human_readable_hex(parts[1]),
                        "REMOTE".bright_red().bold(),
                        human_readable_hex(&fingerprint),
                        format!(
                            "you may manually remove line {} in the wgd_known_hosts file",
                            n
                        )
                        .bold()
                    );
                    return SavedState::Mismatch;
                }
            }
        }
    }

    return SavedState::NotSaved;
}

fn save_fingerprint(hostname: &str, fingerprint: &str) {
    // save fingerprint to wgd_known_hosts
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("wgd_known_hosts");

    if let Ok(mut f) = file {
        // append fingerprint to file
        if let Ok(_) = f.write_vectored(&[
            IoSlice::new(hostname.as_bytes()),
            IoSlice::new(b" "),
            IoSlice::new(fingerprint.as_bytes()),
            IoSlice::new(b"\n"),
        ]) {
            warn!(
                "Permanently added '{}' to the list of known hosts.",
                hostname
            );
        }
    }
}
