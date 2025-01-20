# Hot Cheese 🔥🧀  

**Hot Cheese** is a secure HTTPS server designed for the **distribution of private keys** during live service restarts. It leverages the macOS **Keychain** for secure storage and **Touch ID** for request-level authorization. All communication is protected with **SSL certificate pinning** and **Diffie-Hellman key exchange (via `df-share`)**, ensuring robust encryption.

---

## Key Features  

1. **Secure Key Management**:  
   - Master encryption key is stored as a **generic password** in the macOS Keychain.  
   - Users can define their own master encryption key, its size, and method of generation.  
   - Encrypted keys are stored on disk in a user-specified directory.  
   - Each request to decrypt keys requires **Touch ID authorization**.  

2. **End-to-End Encryption**:  
   - Diffie-Hellman key exchange ensures that keys are encrypted for the requesting client.  
   - Enforced **SSL certificate pinning** ensures communication integrity.

3. **Customizable Backend Configuration**:  
   - Specify:
     - **Keychain entry name** (service name).
     - **Keychain account name** (user-defined).  
     - **Storage directory** for encrypted keys.  

4. **Designed for Port Forwarding**:  
   - Forward its HTTPS port to a remote VM for seamless integration with distributed systems.  

---

## Use Case  

When restarting live services requiring private keys, **Hot Cheese** serves as a secure backend to distribute keys on demand. Clients authenticate and securely retrieve keys over HTTPS with strong encryption.  

---

## Backup Strategy  

1. **Master Encryption Key**:  
   - The master encryption key is stored in the macOS Keychain.  
   - You can **add, modify, or export** the key using the **Keychain Access** UI:
     - Open **Keychain Access** (located in `/Applications/Utilities`).
     - To add a new key:
       1. Go to **File > New Password Item**.
       2. Set the **Keychain Item Name** to match the service name (e.g., `com.example.myapp`).
       3. Set the **Account Name** to your configured account name (e.g., `myusername`).
       4. Add a strong password as the master encryption key.

2. **Encrypted Keys**:  
   - Periodically back up the directory where the encrypted keys are stored (configured in `main.rs`).

---

## How It Works  

1. **Key Storage**:  
   - Encrypted keys are stored in the configured directory on disk.  
   - The master encryption key is securely stored in the macOS Keychain and is used to encrypt/decrypt the key files.  
   - Each decryption request is authorized using **Touch ID**.

2. **Secure HTTPS**:  
   - The server runs with a pinned SSL certificate (`ssl-cert.pem`).  
   - Diffie-Hellman ensures that keys are only decryptable by the intended client.

3. **Customizable Setup**:  
   - Users can define the Keychain service and account name for the master key and specify the directory for encrypted keys.

4. **Client Integration**:  
   - The client (`HotCheeseAgent`) communicates with the server using HTTPS.  
   - It retrieves and decrypts keys using a shared secret established via Diffie-Hellman.

---

## Installation  

### Server Setup  

1. **Generate a Self-Signed Certificate**:  
   Use the following command to create the SSL certificate and private key:
   ```bash
   sh script/generate_certs.sh
   ```

2. **Set Up the Master Key**:  
   - Open **Keychain Access**.  
   - Go to **File > New Password Item**.  
   - Set:
     - **Keychain Item Name**: `com.example.myapp` (or your desired service name).  
     - **Account Name**: `myusername` (or your desired account name).  
     - **Password**: A strong, randomly generated password.  
   - Save the item.

3. **Start the Server**:  
   Customize `main.rs` to specify your Keychain entry and storage directory:
   ```rust
   run_server(Box::new(MacBackend::new(
       "com.example.myapp", // Keychain service name
       "myusername",        // Keychain account name
       "~/HOT_CHEESE_KEYS", // Encrypted key storage directory
   )))
   .unwrap();
   ```
   Then start the server:
   ```bash
   cargo run --release
   ```

---

### Client API  

1. **Create a Client**:
   ```rust
   let client = HotCheeseAgent::new("https://localhost:5555");
   ```

2. **Health Check**:
   ```rust
   let health = client.health().unwrap();
   println!("Health: {}", health);
   ```

3. **Generate Keys**:
   ```rust
   client.generate("key_name").unwrap();
   ```

4. **Read Keys**:
   ```rust
   let key = client.read("key_name").unwrap();
   println!("Decrypted Key: {:?}", key);
   ```

---

## Example Workflow  

1. **Spin Up the Server**:  
   Deploy the server locally with the desired storage directory and Keychain configuration.  
   Forward its port to a remote VM for broader access if necessary.

2. **Generate Keys if Needed**:  
   ```rust
   client.generate("service_key");
   ```

3. **Client Retrieves a Key**:  
   ```rust
   let key = client.read("service_key");
   ```

4. **Secure Distribution**:  
   The retrieved key is securely sent over HTTPS and decrypted using Diffie-Hellman exchange.

---

## Security Highlights  

- **Customizable Master Encryption Key**:  
   - Users can define how the master key is generated and stored in the Keychain.  

- **Touch ID Authorization**:  
   - Ensures that only authorized users can decrypt sensitive keys.  

- **SSL Certificate Pinning**:  
   - Prevents man-in-the-middle (MITM) attacks.  

- **Diffie-Hellman Key Exchange**:  
   - Ensures end-to-end encryption between server and client.

---

## FAQ  

**Q: Why use Touch ID?**  
A: Touch ID ensures only authorized requests can decrypt sensitive keys, adding an extra layer of security.  

**Q: Can I use this on non-macOS systems?**  
A: No, this is designed specifically for macOS due to its reliance on the Keychain and Touch ID. However, the `BackendImpl` trait allows for extending to other platforms.  

**Q: What happens if I lose access to the master key?**  
A: Without the master key in the Keychain, the encrypted keys cannot be decrypted. Ensure you back up the master key and the encrypted files.

**Q: How do I customize the storage folder or Keychain entry name?**  
A: Update the `MacBackend::new` parameters in `main.rs` to specify:
   - **Keychain service name** (e.g., `"com.example.myapp"`)  
   - **Keychain account name** (e.g., `"myusername"`)  
   - **Directory for encrypted keys** (e.g., `"~/HOT_CHEESE_KEYS"`)  

**Q: How do I manage the master encryption key?**  
A: Use **Keychain Access** to add, update, or export the master key:
   - **Add a Key**: Go to **File > New Password Item** and fill in the service name, account name, and password.  

---

**Hot Cheese** 🔥🧀 — Securely distributing keys with the perfect blend of encryption, macOS security, and seamless integration.