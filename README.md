# Cryptography and Blockchain Examples in Python

This repository contains four Python scripts demonstrating cryptography and blockchain concepts using the `cryptography` library.

## File 1: Simple Encryption and Decryption

### `app.py`

This script showcases a basic example of asymmetric encryption and decryption using the RSA algorithm.

#### How to Use:

1. Install the required library:

    ```bash
    pip install cryptography
    ```

2. Run the script:

    ```bash
    python app.py
    ```

3. The script will generate a key pair, encrypt the message "Hello world," and then decrypt it, printing the decrypted message.

---

## File 2: Improved Encryption, Decryption, and Signature Verification

### `app2.py`

This script builds upon the first example by introducing message signing and verification.

#### How to Use:

1. Install the required library:

    ```bash
    pip install cryptography
    ```

2. Run the script:

    ```bash
    python app2.py
    ```

3. The script will generate a key pair, encrypt the message "Hello world," sign the message, verify the signature, and then decrypt the message, printing the decrypted message and signature validity.

---

## File 3: Simple Blockchain Implementation

### `app3.py`

This script implements a basic blockchain with transaction signing and verification.

#### How to Use:

1. Install the required library:

    ```bash
    pip install cryptography
    ```

2. Run the script:

    ```bash
    python app3.py
    ```

3. The script will create a blockchain with a genesis block, generate a key pair for a participant, create a new block, add a transaction to the block, and print the hash of each block in the blockchain.

---

## File 4: Blockchain Command-Line Interface (CLI)

### `blockchain-cli.py`

This script introduces a command-line interface for interacting with a simple blockchain. Users can add transactions and view the blockchain.

#### How to Use:

1. Install the required library:

    ```bash
    pip install cryptography
    ```

2. Run the script:

    ```bash
    python blockchain-cli.py
    ```

3. Follow the on-screen prompts to add transactions or view the blockchain.

---

# Blockchain Python Implementation

This project contains a simple implementation of a blockchain in Python. It includes three versions of the implementation: manual, automatic, and a final version that combines both.

## Features

- **blockchain-manually.py**: Manual implementation of a blockchain with user input for transactions.
- **blockchain-automatically.py**: Automated implementation with randomly generated transactions.
- **blockchain-final.py**: Final version combining manual and automated transactions.

## Prerequisites

Make sure you have Python installed on your machine.

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/ornur/app1.git
   ```

2. Navigate to the project directory:

   ```bash
   cd app1
   ```

3. Run the desired blockchain script:

    ```bash
    python blockchain-manually.py
    ```
or

    ```bash
    python blockchain-automatically.py
    ```
or

    ```bash
    python blockchain-final.py
    ```

## Usage

Follow the on-screen instructions to add transactions, view the blockchain, and check the transaction history.

## Contributing

Feel free to explore and modify these scripts to understand the concepts of encryption, decryption, signature generation, verification, and basic blockchain functionality.
