// === Encrypted Notes Vault ===
// A command-line app to securely store, view, and delete encrypted notes.
// Built using:
// - `clap` for argument parsing
// - `serde` + `serde_json` for data storage
// - `aes-gcm` for encryption
// - `rpassword` for silent password input
// - `sha2` for password-based key derivation

// ----------------- Imports -----------------
use clap::{Parser, Subcommand}; // Command-line parser
use serde::{Deserialize, Serialize}; // For JSON serialization
use std::fs::File;
use std::io::{self, Read, Write};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce}; // AES-GCM cipher
use aes_gcm::aead::{Aead, OsRng, generic_array::GenericArray}; // Cryptography helpers
use rand::RngCore; // Secure RNG
use base64::{engine::general_purpose, Engine as _}; // For encoding binary data
use sha2::{Sha256, Digest}; // SHA-256 hasher
use rpassword::read_password; // Secure terminal input

const VAULT_FILE: &str = "vault.json"; // The file where encrypted notes are saved

// ----------------- CLI Argument Structures -----------------

/// Main CLI entrypoint — handles subcommands using `clap`
#[derive(Parser, Debug)]
#[command(name = "vault", about = "Manage your encrypted notes")]
struct Args {
    #[command(subcommand)]
    command: VaultCommands,
}

/// Subcommands for interacting with the vault
#[derive(Subcommand, Debug)]
enum VaultCommands {
    /// Add a new encrypted note
    New {
        title: String,
        content: String,
    },
    /// List decryptable note titles
    List,
    /// Read a note by its title
    Read {
        title: String,
    },
    /// Delete a note by its title (if it can be decrypted)
    Delete {
        title: String,
    },
}

// ----------------- Data Structure -----------------

/// Struct to store a note with encrypted content
#[derive(Serialize, Deserialize, Debug)]
struct Note {
    title: String,
    content: String, // Encrypted base64 string
    nonce: String,   // Base64-encoded nonce for AES-GCM
}

// ----------------- Utility Functions -----------------

/// Prompt the user to enter a password silently
fn prompt_password() -> String {
    print!("🔑 Enter password: ");
    io::stdout().flush().unwrap(); // Ensure prompt shows before input
    read_password().unwrap_or_default() // Return empty if input fails
}

/// Derives a 256-bit AES key from a password using SHA-256
fn derive_key_from_password(password: &str) -> GenericArray<u8, typenum::U32> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    GenericArray::clone_from_slice(&result) // Required format for AES-GCM
}

/// Encrypt note content and return (ciphertext_base64, nonce_base64)
fn encrypt_note_content(content: &str, key: &GenericArray<u8, typenum::U32>) -> (String, String) {
    let cipher = Aes256Gcm::new(key);

    // Generate a random 96-bit (12-byte) nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the content
    let ciphertext = cipher
        .encrypt(nonce, content.as_bytes())
        .expect("Encryption failed");

    (
        general_purpose::STANDARD.encode(&ciphertext),
        general_purpose::STANDARD.encode(&nonce_bytes),
    )
}

/// Decrypts note content, returning the original plaintext if successful
fn decrypt_note_content(ciphertext_b64: &str, nonce_b64: &str, key: &GenericArray<u8, typenum::U32>) -> Option<String> {
    let cipher = Aes256Gcm::new(key);

    // Decode base64 strings back into bytes
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).ok()?;
    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).ok()?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Attempt decryption
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
    String::from_utf8(plaintext).ok()
}

/// Load all notes from the vault file
fn load_notes() -> Vec<Note> {
    if let Ok(mut file) = File::open(VAULT_FILE) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Save all notes to the vault file
fn save_notes(notes: &[Note]) {
    let json = serde_json::to_string_pretty(notes).unwrap();
    let mut file = File::create(VAULT_FILE).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

// ----------------- Main Program -----------------

fn main() {
    let args = Args::parse(); // Parse command-line arguments
    let password = prompt_password(); // Ask user for master password
    let key = derive_key_from_password(&password); // Turn password into AES key
    let mut notes = load_notes(); // Load existing notes from file

    match args.command {
        VaultCommands::New { title, content } => {
            let (encrypted_content, nonce) = encrypt_note_content(&content, &key);
            notes.push(Note {
                title,
                content: encrypted_content,
                nonce,
            });
            save_notes(&notes);
            println!("✅ Note added.");
        }

        VaultCommands::List => {
            println!("🔐 Decryptable notes:");
            for note in &notes {
                if decrypt_note_content(&note.content, &note.nonce, &key).is_some() {
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

            // Keep only notes we *don't* want to delete
            notes.retain(|note| {
                if note.title == title {
                    match decrypt_note_content(&note.content, &note.nonce, &key) {
                        Some(_) => {
                            println!("🗑️ Note '{}' deleted.", note.title);
                            false // Delete this note
                        }
                        None => {
                            println!("❌ Cannot delete '{}': Wrong password.", note.title);
                            true // Keep this note
                        }
                    }
                } else {
                    true // Keep all other notes
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
