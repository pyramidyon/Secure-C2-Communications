# Secure C2 Communications Encrypt & Sign Algorithm

**Proof of Concept (PoC):**

https://github.com/pyramidyon/Secure-C2-Communications/assets/88564775/56321059-2fde-4ef0-b05f-d05070e8caed

This repository demonstrates a **Proof of Concept** on how `DGA/P2P Malware` leverages cryptographic techniques along with a corresponding public signing key to verify signatures and confirm the integrity and authenticity of communications. The primary rationale for enhancing the integrity and authenticity of messages is to ensure that, although reverse engineers may analyze and modify the malware binaries they have on their system, they cannot control the malware's dynamically generated command and control (C2) endpoints and the rest of the hive, which are uniquely managed by the malware author. This feature is particularly valuable for malware authors aiming to maintain exclusive control over their malware networks.

## PoC Features

- **XOR Encryption**: Implements a straightforward yet robust symmetric encryption using a cyclical key approach, providing a basic level of security by obfuscating the transmitted data.
- **Ed25519 Digital Signature**: Employs the Ed25519 algorithm, a public-key signature system known for its strength and efficiency, to generate and verify signatures. This ensures that messages remain tamper-proof and originate from a genuine source.
- **Security Check**: Integrates mechanisms to authenticate signatures before proceeding with message decryption, adding an additional layer of security by preventing unauthorized access to the message content.
