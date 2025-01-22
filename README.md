# File Encryption and Decryption with RSA

This Python project demonstrates file encryption and decryption using the RSA algorithm. It allows users to select a file, generate RSA key pairs, encrypt the file, and decrypt it back to its original content. The project uses the `cryptography` library for cryptographic operations and `easygui` for file selection through a GUI dialog box.

## Features
- **RSA Key Pair Generation**: Generates a secure private and public key pair using the RSA algorithm.
- **File Encryption**: Encrypts a selected file using the public RSA key and saves the encrypted file with a `.enc` extension.
- **File Decryption**: Decrypts the encrypted file using the private RSA key and saves the decrypted file with a `.dec` extension.
- **User-Friendly Interface**: Uses `easygui` for simple file selection.

## Libraries Used
- `os`: For file path validation.
- `easygui`: To create a dialog box for file selection.
- `cryptography.hazmat.primitives`: For RSA key generation, encryption, and decryption.
- `cryptography.hazmat.primitives.serialization`: For saving and loading RSA keys in PEM format.

## How It Works
1. **Select a File**: A dialog box prompts the user to select a `.txt` file for encryption.
2. **Generate RSA Keys**: The program generates a public-private key pair and saves them as `public_key.pem` and `private_key.pem`.
3. **Encrypt the File**: The selected file is encrypted using the public key and saved with a `.enc` extension.
4. **Decrypt the File**: The encrypted file is decrypted using the private key and saved with a `.dec` extension.

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/GoldenEye10/rsa-file-encryption.git
   cd rsa-file-encryption
   ```

2. **Install Dependencies**:
   Make sure you have Python 3 installed. Install the required libraries:
   ```bash
   pip install easygui cryptography
   ```

3. **Run the Program**

## Project Structure
```
.
├── rsa_encryption.py     # Main script containing all functions and logic
├── private_key.pem   # Generated private key (created at runtime)
├── public_key.pem    # Generated public key (created at runtime)
└── README.md         # Project documentation
```

## Key Functions
- **PS_get_file_path()**: Prompts the user to select a file for encryption using a dialog box.
- **PS_generate_rsa_key_pair()**: Generates and saves RSA key pairs.
- **PS_encrypt_file()**: Encrypts the selected file using the public key.
- **PS_decrypt_file()**: Decrypts the encrypted file using the private key.
- **main()**: Driver function that coordinates all operations.

## Notes
- Ensure the input file is a `.txt` file, as the program reads the content as text.
- Keep the `private_key.pem` file secure, as it is required for decryption.

## References
- [Cryptography Documentation](https://cryptography.io/en/latest/)
- [EasyGUI Documentation](https://easygui.readthedocs.io/en/latest/)
- [RSA Encryption - Stack Overflow](https://stackoverflow.com/questions/)


