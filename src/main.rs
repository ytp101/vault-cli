use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; // AES-GCM
use aes_gcm::aead::{Aead, OsRng, generic_array::GenericArray};
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Sha256, Digest};

const VAULT_FILE: &str = "vault.json";

#[derive(Parser, Debug)]
#[command(name = "vault", about = "Manage your encrypted notes")]
struct Args {
    #[command(subcommand)]
    command: VaultCommands,
}

#[derive(Subcommand, Debug)]
enum VaultCommands {
    New {
        title: String,
        content: String,
    },
    List,
    Read {
        title: String,
    },
    Delete {
        title: String,
    },
}

#[derive(Serialize, Deserialize, Debug)]
struct Note {
    title: String,
    content: String,
    nonce: String,
}

// Prompt the user for a password
fn prompt_password() -> String {
    use rpassword::read_password;

    print!("🔑 Enter password: ");
    io::stdout().flush().unwrap();
    read_password().unwrap_or_default()
}

// Derive a 256-bit key from the password using SHA-256
fn derive_key_from_password(password: &str) -> GenericArray<u8, typenum::U32> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    GenericArray::clone_from_slice(&result)
}

// Encrypt the note content
fn encrypt_note_content(content: &str, key: &GenericArray<u8, typenum::U32>) -> (String, String) {
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, content.as_bytes()).expect("Encryption failed");
    (
        general_purpose::STANDARD.encode(&ciphertext),
        general_purpose::STANDARD.encode(&nonce_bytes),
    )
}

// Decrypt the note content
fn decrypt_note_content(ciphertext_b64: &str, nonce_b64: &str, key: &GenericArray<u8, typenum::U32>) -> Option<String> {
    let cipher = Aes256Gcm::new(key);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).ok()?;
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).ok()?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}

// Load notes from the vault file
fn load_notes() -> Vec<Note> {
    if let Ok(mut file) = File::open(VAULT_FILE) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    }
}

// Save notes to the vault file
fn save_notes(notes: &[Note]) {
    let json = serde_json::to_string_pretty(notes).unwrap();
    let mut file = File::create(VAULT_FILE).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

fn main() {
    let args = Args::parse();
    let password = prompt_password();
    let key = derive_key_from_password(&password);
    let mut notes = load_notes();

    match args.command {
        VaultCommands::New { title, content } => {
            let (encrypted_content, nonce) = encrypt_note_content(&content, &key);
            notes.push(Note { title, content: encrypted_content, nonce });
            save_notes(&notes);
            println!("✅ Note added.");
        }
        VaultCommands::List => {
            println!("🔐 Decryptable notes:");
            for note in &notes {
                if let Some(_) = decrypt_note_content(&note.content, &note.nonce, &key) {
                    println!("📌 {}", note.title);
                }
            }
        }
        VaultCommands::Read { title } => {
            if let Some(note) = notes.iter().find(|n| n.title == title) {
                match decrypt_note_content(&note.content, &note.nonce, &key) {
                    Some(decrypted) => println!("🔓 Content: {}", decrypted),
                    None => println!("❌ Failed to decrypt. Wrong password?"),
                }
            } else {
                println!("❌ Note not found.");
            }
        }
        VaultCommands::Delete { title } => {
            let len_before = notes.len();
        
            notes.retain(|note| {
                if note.title == title {
                    match decrypt_note_content(&note.content, &note.nonce, &key) {
                        Some(_) => {
                            println!("🗑️ Note '{}' deleted.", note.title);
                            false // drop this note
                        }
                        None => {
                            println!("❌ Cannot delete '{}': Wrong password.", note.title);
                            true // keep it
                        }
                    }
                } else {
                    true // keep all other notes
                }
            });
        
            if notes.len() < len_before {
                save_notes(&notes);
            } else {
                println!("❌ Note not found or password mismatch.");
            }
        }
        
    }
}
