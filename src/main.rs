use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

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
}

// Load the vault (or create an empty one)
fn load_notes() -> Vec<Note> {
    if let Ok(mut file) = File::open(VAULT_FILE) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    }
}

// Save notes to file 
fn save_notes(notes: &[Note]) {
    let json = serde_json::to_string_pretty(notes).unwrap();
    let mut file = File::create(VAULT_FILE).unwrap();
    file.write_all(json.as_bytes()).unwrap();
}

fn main() {
    let args = Args::parse();
    let mut notes = load_notes();
  
    match args.command {
        VaultCommands::New { title, content } => {
            notes.push(Note { title, content });
            save_notes(&notes);
            println!("✅ Note added.");
        }
        VaultCommands::List => {
            for note in &notes {
                println!("📌 {}", note.title);
            }
        }
        VaultCommands::Read { title } => {
            if let Some(note) = notes.iter().find(|n| n.title == title) {
                println!("🔓 Content: {}", note.content);
            } else {
                println!("❌ Note not found.");
            }
        }
        VaultCommands::Delete { title } => {
            let len_before = notes.len(); 
            notes.retain(|n| n.title != title);
            if notes.len() < len_before {
                save_notes(&notes);
                println!("🗑️ Note deleted.");
            } else {
                println!("❌ Note not found.");
            }
        }
    }
}