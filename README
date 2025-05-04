# 🔐 Vault CLI

A simple command-line tool to **create, read, list, and delete encrypted notes**. Notes are stored securely using AES-256-GCM encryption. Built with 💖 using Rust!

## ✨ Features

- Add new encrypted notes
- List decryptable notes
- Read individual notes
- Securely delete notes
- Password-based encryption using SHA-256 derived key
- Notes stored locally in `vault.json`

## 🚀 Getting Started

### 🛠 Requirements

- Rust (https://www.rust-lang.org/tools/install)

### 📦 Installation

```bash
git clone https://github.com/ytp101/vault-cli.git
cd vault-cli
cargo build --release
```

# 🧪 Run 
```bash
cargo run -- <command>
```

# 🔧 Usage 
### Add a New Note 
```
cargo run -- new "Note Title" "Secret content goes here"
```
You'll be prompted for a password to encrypt the content.

### List Notes
```
cargo run -- list
```
Only decryptable note titles will be shown.

### Read a Note 
```
cargo run -- read "Note Title"
```
If the password is correct, the decrypted content will be displayed.

### Delete a Note
```
cargo run -- delete "Note Title"
```
Note will only be deleted if the password is correct.

## 📁 File Structure
* `vault.json`: Stores all encrypted notes (encrypted content + nonce)
* `main.rs`: Core logic (CLI, encryption, storage)

### 🔐 Security Notes 
* Password is never stored.
* If you lose your password, the encrypted content is unrecoverable.
* Vault encryption uses:
    * AES-256-GCM for authenticated encryption
    * SHA-256 to derive keys from passwords
    * Base64 for storing encrypted values

### 🛡️ Dependencies

- [`clap`](https://docs.rs/clap/) – Command-line argument parsing.
- [`aes-gcm`](https://docs.rs/aes-gcm/) – AES-256 GCM encryption/decryption.
- [`serde`](https://docs.rs/serde/) + [`serde_json`](https://docs.rs/serde_json/) – Serialization and deserialization of data.
- [`base64`](https://docs.rs/base64/) – Encoding binary data as Base64 for safe storage.
- [`sha2`](https://docs.rs/sha2/) – SHA-256 hashing algorithm used for password key derivation.
- [`rpassword`](https://docs.rs/rpassword/) – Read passwords from stdin without echoing.



### 🧠 Disclaimer
This is a learning project. Don’t use it to store nuclear codes or grandma’s cookie recipe unless you’ve reviewed the code and understand its security tradeoffs.

### License MIT License
See the LICENSE file for more information.