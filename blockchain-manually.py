import datetime
import math
import random

class Block:
    def __init__(self, transactions, previous_block_hash=None):
        self.transactions = transactions
        self.previous_block_hash = previous_block_hash
        self.timestamp = datetime.datetime.now()
        self.nonce = 0

    def hash_block(self):
        transaction_str = ",".join(str(tx) for tx in self.transactions)
        block_str = f"{transaction_str}{self.previous_block_hash}{self.timestamp}{self.nonce}"
        return self.simple_hash(block_str)

    @staticmethod
    def simple_hash(data):
        return hash(data) % (10 ** 8)

def generate_key_pair():
    # Simple RSA key generation for educational purposes
    p = generate_large_prime()
    q = generate_large_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Common choice for the public exponent
    d = mod_inverse(e, phi)
    public_key = (n, e)
    private_key = (n, d)
    return private_key, public_key

def generate_large_prime():
    # Simple prime number generation for educational purposes
    while True:
        num = random.getrandbits(16)
        if is_prime(num):
            return num

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True

def mod_inverse(a, m):
    # Simple modular inverse calculation for educational purposes
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def rsa_encrypt(message, public_key):
    n, e = public_key
    return pow(message, e, n)

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)

def sign_message(private_key, message):
    message_bytes = message.encode('utf-8')
    message_hash = Block.simple_hash(message)
    signature = rsa_encrypt(message_hash, private_key)
    return signature

def verify_signature(public_key, message, signature):
    message_bytes = message.encode('utf-8')
    message_hash = Block.simple_hash(message)
    decrypted_signature = rsa_decrypt(signature, public_key)
    return decrypted_signature == message_hash

def create_genesis_block():
    return Block(transactions=['Genesis Transaction'])

def add_transaction_to_block(block, sender_private_key, recipient_public_key, amount, transaction_history):
    sender_public_key = sender_private_key[1]  # Extract the public key from the private key
    transaction = {
        "sender": sender_public_key,
        "recipient": recipient_public_key,
        "amount": amount
    }

    signature = sign_message(sender_private_key, str(transaction))

    if not verify_signature(sender_public_key, str(transaction), signature):
        print("Transaction signature verification failed.")
        return None

    block.transactions.append({
        "transaction": transaction,
        "signature": signature
    })

    transaction_history.append({
        "block_hash": block.hash_block(),
        "transaction": {
            "sender": sender_public_key,
            "recipient": recipient_public_key,
            "amount": amount
        },
        "signature": signature
    })

def display_blockchain(blockchain, transaction_history):
    for i, block in enumerate(blockchain):
        print(f"Block {i + 1}: Hash - {block.hash_block()}")

        for tx_data in block.transactions:
            if isinstance(tx_data, str) and tx_data == "Genesis Transaction":
                print("Genesis block detected. No transactions to display.")
            else:
                # Access transaction data assuming a list of transaction dictionaries
                transaction = tx_data[0]
                sender = transaction['sender'].decode('utf-8')
                recipient = transaction['recipient'].decode('utf-8')
                print(f"    Sender: {sender}")
                print(f"    Recipient: {recipient}")
                print(f"    Amount: {transaction['amount']}")
                print(f"    Signature: {tx_data['signature']}")
        print("\n")

    print("Transaction History:")
    for tx_data in transaction_history:
        transaction = tx_data['transaction']
        print(f"Block Hash: {tx_data['block_hash']}")
        print(f"    Sender: {transaction['sender']}")
        print(f"    Recipient: {transaction['recipient']}")
        print(f"    Amount: {transaction['amount']}")
        print(f"    Signature: {tx_data['signature']}")
        print("\n")

def main():
    print("Welcome to the Blockchain CLI!")

    sender_private_key, sender_public_key = generate_key_pair()
    blockchain = [create_genesis_block()]
    transaction_history = []

    while True:
        print("\n1. Add Transaction")
        print("2. View Blockchain")
        print("3. View Transaction History")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            recipient_public_key = input("Enter recipient's public key: ")
            while True:
                try:
                    amount = float(input("Enter transaction amount: "))
                    break  # Break the loop if a valid amount is entered
                except ValueError:
                    print("Invalid amount. Please enter a number.")
                    new_block = Block(transactions=[], previous_block_hash=blockchain[-1].hash_block())
                    add_transaction_to_block(new_block, sender_private_key, recipient_public_key, amount,
                                             transaction_history)
                    blockchain.append(new_block)
                    print("Transaction added successfully!")
                    break

        elif choice == "2":
            display_blockchain(blockchain, transaction_history)

        elif choice == "3":
            print("\nTransaction History:")
            for tx in transaction_history:
                print(f"Block Hash: {tx['block_hash']}")
                print(f"    Sender: {tx['transaction']['sender']}")
                print(f"    Recipient: {tx['transaction']['recipient']}")
                print(f"    Amount: {tx['transaction']['amount']}")
                print(f"    Signature: {tx['signature']}")
                print("\n")

        elif choice == "4":
            print("Exiting the Blockchain CLI. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()

