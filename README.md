# Hot Cheese 🔥🧀  

**Hot Cheese** is a secure HTTPS server designed for the **distribution of private keys** during live service restarts. It leverages the macOS **Keychain** for secure storage and **Touch ID** for request-level authorization. All communication is protected with **SSL certificate pinning** and **Diffie-Hellman key exchange (via [df-share](https://github.com/copiumnicus/df-share))**, ensuring robust encryption.

---

## Table of Contents

1. [Key Features](#key-features)  
2. [How It Works](#how-it-works)  
3. [Installation & Setup](#installation--setup)  
   - [1. Create a Cheese Config](#1-create-a-cheese-config)  
   - [2. Add a Master Password](#2-add-a-master-password)  
   - [3. (Optional) Add an Existing Private Key](#3-optional-add-an-existing-private-key)  
   - [4. Generate SSL Certificates](#4-generate-ssl-certificates)  
   - [5. Build & Run Hot Cheese](#5-build--run-hot-cheese)  
4. [Server Endpoints](#server-endpoints)  
5. [Client Integration Example](#client-integration-example)  
6. [Backup Strategy](#backup-strategy)  
7. [Security Highlights](#security-highlights)  
8. [FAQ](#faq)  

---

## Key Features  

1. **Secure Key Management**  
   - **Master encryption key** stored as a **generic password** in the macOS Keychain.  
   - Users can define their own master encryption key, its size, and method of generation.  
   - Encrypted keys are stored on disk in a user-specified directory.  
   - Each request to decrypt keys requires **Touch ID authorization**.  

2. **End-to-End Encryption**  
   - **Diffie-Hellman key exchange** ensures that keys are encrypted specifically for the requesting client.  
   - **SSL certificate pinning** to prevent man-in-the-middle attacks.  

3. **Customizable Backend Configuration**  
   - Specify:
     - **Keychain entry name** (service name).  
     - **Keychain account name** (user-defined).  
     - **Storage directory** for encrypted keys.  
   - All of these can be managed via a simple JSON config (see [Installation & Setup](#installation--setup)).  

4. **Port Forwarding-Friendly**  
   - Forward its HTTPS port to a remote VM for seamless integration with distributed systems.  

---

## How It Works  

1. **Key Storage**  
   - **Encrypted private keys** are stored in a designated on-disk folder.  
   - A **master encryption key** (from the macOS Keychain) encrypts/decrypts those keys.  
   - Each decryption request is further gated by **Touch ID** (physical user presence required).  

2. **Secure HTTPS**  
   - The server uses a pinned SSL certificate (e.g., `ssl-cert.pem`).  
   - **Diffie-Hellman** ephemeral exchange ensures only the requesting client can decrypt the key.  

3. **Customizable Setup**  
   - Configuration is read from a JSON file (e.g., `cheese_config.json`):
     ```json
     {
       "service": "com.example.myapp",
       "account": "myusername",
       "store": "/Users/myusername/hot_cheese_keys"
     }
     ```
   - You can edit `cheese_config.json` to fit your environment (service name, account name, storage path).

4. **Client Integration**  
   - A corresponding client (e.g., `HotCheeseAgent`) can securely retrieve and decrypt keys over HTTPS.  

---

## Installation & Setup  

Follow these steps to get **Hot Cheese** up and running on your macOS system.

### 1. Create a Cheese Config  

Create a JSON file called `cheese_config.json` (the default name expected by the examples below). Customize its values according to your environment:

```jsonc
{
  "service": "com.example.myapp",        // Keychain service name
  "account": "myusername",               // Keychain account name
  "store": "/Users/myusername/hot_keys"  // Directory for storing encrypted keys
}
```

Place `cheese_config.json` in the same folder as your code or adjust the examples accordingly.

### 2. Add a Master Password  

You can manually add a master password (a generic password entry) to your macOS Keychain in two ways:

**Option A: Using Keychain Access**  
1. Open **Keychain Access** (located in `/Applications/Utilities`).  
2. Go to **File > New Password Item**.  
3. Under **Keychain Item Name**, enter the value of `service` from `cheese_config.json`.  
4. Under **Account Name**, enter the value of `account` from `cheese_config.json`.  
5. Under **Password**, supply a strong alphanumeric password.  
6. Click **Add**.

**Option B: Using the Provided Example Script**  
If you have `cheese_config.json` set up, run the `add_master` example to automate the process in your shell:

```bash
cargo run --example add_master
```

You will be prompted for the master password (twice to confirm). This script uses the `security add-generic-password` command under the hood.

### 3. (Optional) Add an Existing Private Key  

If you already have a private key you want to store securely, use the `add_existing` example:

```bash
cargo run --example add_existing <key_name>
```

1. You will be prompted to enter the **hex-encoded** private key (with or without `0x`).  
2. You will also be prompted for Touch ID authorization (to verify device ownership).  
3. The private key is encrypted using the master key from Keychain and stored in the `store` directory.  

**Note**: If the `<key_name>` file already exists, the process will abort to avoid overwriting.

### 4. Generate SSL Certificates  

Use the provided script to generate a self-signed SSL certificate (and a private key) for development/testing:

```bash
sh script/generate_certs.sh
```

This will create `ssl-cert.pem` and `ssl-key.pem`.

### 5. Build & Run Hot Cheese  

You can build and install the **Hot Cheese** binary with:

```bash
#!/bin/bash
cargo install --force --locked --profile release --bin hot_cheese --path .
```

Alternatively, just run it in place:

```bash
cargo run --release
```

The main entry point (in `main.rs`) looks like:

```rust
use hot_cheese::{run_server, Config, MacBackend};
use std::sync::Arc;
use hyper::{Request, Response, Body};

#[tokio::main]
async fn main() {
    // Load configuration from 'cheese_config.json'
    let bytes = include_bytes!("./cheese_config.json");
    let conf: Config = serde_json::from_slice(bytes.as_slice()).unwrap();

    // Create the macOS Keychain-based backend
    let backend = MacBackend::new(&conf.service, &conf.account, &conf.store);

    // Run the secure HTTPS server
    run_server(Box::new(backend)).unwrap();
}
```

This will:  
1. Read your config from `cheese_config.json`.  
2. Initialize the macOS Keychain backend.  
3. Start the HTTPS server with the pinned certificates.  

---

## Server Endpoints  

The core server logic (an example excerpt from `service_impl`) maps incoming paths to **Hot Cheese** actions:

- **`/health`**  
  - Returns `"ok"` if the server is running.

- **`/read/<key_name>`**  
  - Reads the request body (for Diffie-Hellman parameters) and decrypts the requested `<key_name>` file.  
  - Returns the encrypted result (decryptable only by the client that initiated the DH exchange).

- **`/evm_generate/<key_name>`**  
  - Generates a new Ethereum-compatible key (private key in the store).

- **`/evm_address/<key_name>`**  
  - Returns the Ethereum address derived from the `<key_name>` private key.

**Note**:  
- All private key decryption operations will prompt for **Touch ID**.  
- The example code captures any errors and returns `INTERNAL_SERVER_ERROR` if something fails.

---

## Client Integration Example  

Suppose you have a Rust client that uses **df-share** or a similar library to handle the Diffie-Hellman exchange. You might write something like:

```rust
/// You probably should copy HotCheeseAgent from `pin_cert` example and make it your own in your private key consumers
fn main() {
    // Create a HotCheeseAgent to talk to the local server
    let client = HotCheeseAgent::new("https://localhost:5555");

    // Health check
    let health = client.health().expect("Server health request failed");
    println!("Health: {}", health); // "ok"

    // Generate a new key if you need one
    client.generate("my_service_key").expect("Key generation failed");

    // Retrieve (decrypt) the key
    let key = client.read("my_service_key").expect("Key read failed");
    println!("Decrypted Key: {:?}", key);
}
```

The **Diffie-Hellman** handshake and **SSL certificate pinning** happen internally, ensuring end-to-end encryption of the private key.

---

## Backup Strategy  

1. **Master Encryption Key**  
   - Stored in the macOS Keychain.  
   - Backup is **critical**; losing this key means you cannot decrypt any stored keys.  
   - You can re-add or export it using Keychain Access or re-run the [Add a Master Password](#2-add-a-master-password) step.

2. **Encrypted Keys**  
   - Located in the directory specified by `cheese_config.json` (`"store"`).  
   - Periodically back up this folder (e.g., to an external drive or secure backup system).  

---

## Security Highlights  

- **Customizable Master Encryption Key**  
  - Users define how the master key is generated and stored in the Keychain.  

- **Touch ID Authorization**  
  - Physically ensures that only authorized users can decrypt keys.  

- **SSL Certificate Pinning**  
  - Prevents MITM attacks by verifying the server’s identity.  

- **Diffie-Hellman Key Exchange**  
  - Secures key retrieval by ensuring only the requesting client can decrypt the data.  

---

## FAQ  

1. **Why use Touch ID?**  
   - Touch ID ensures only a physically present, authorized user can decrypt sensitive keys.

2. **Can I use this on non-macOS systems?**  
   - Not out of the box. **Hot Cheese** is built around macOS Keychain and Touch ID. However, you can implement custom backends by providing your own `BackendImpl` if your target platform has a different secure store.

3. **What if I lose access to the master key?**  
   - Without the master key in the Keychain, there is no way to decrypt the on-disk keys. **Always** back up your master key (or keep a secure export of the Keychain item).

4. **How do I customize the storage folder or Keychain entry name?**  
   - Update your `cheese_config.json`:
     ```jsonc
     {
       "service": "com.example.myapp",
       "account": "myusername",
       "store": "/Users/myusername/hot_cheese_keys"
     }
     ```
   - Rebuild or re-run the server to pick up changes.

5. **How do I manage or update the master encryption key?**  
   - Use **Keychain Access** or the [Add a Master Password](#2-add-a-master-password) script to set a new password.  
   - If you change it, the old encrypted files will still require the old key. Be consistent if you rotate keys.

6. **Can I import an existing key?**  
   - Yes, use the `add_existing` script to encrypt and store a hex-encoded private key under the Hot Cheese backend.

---

**Hot Cheese** 🔥🧀 — Securely distributing keys with the perfect blend of encryption, macOS security, and seamless integration. Enjoy your cryptographic fondue!