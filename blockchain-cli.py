from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime

class Block:
    def __init__(self, transactions, previous_block_hash=None):
        self.transactions = transactions
        self.previous_block_hash = previous_block_hash
        self.timestamp = datetime.datetime.now()
        self.nonce = 0

    def hash_block(self):
        transaction_str = ",".join(str(tx) for tx in self.transactions)
        block_str = f"{transaction_str}{self.previous_block_hash}{self.timestamp}{self.nonce}"
        hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_obj.update(block_str.encode())
        return hash_obj.finalize()

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    message_bytes = message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def create_genesis_block():
    return Block(transactions=["Genesis Transaction"])

def add_transaction_to_block(block, sender_private_key, recipient_public_key, amount):
    transaction = {
        "sender": sender_private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
        "recipient": recipient_public_key,
        "amount": amount
    }
    signature = sign_message(sender_private_key, str(transaction))

    if not verify_signature(recipient_public_key, str(transaction), signature):
        print("Transaction signature verification failed.")
        return None

    block.transactions.append({
        "transaction": transaction,
        "signature": signature
    })

def display_blockchain(blockchain):
    for i, block in enumerate(blockchain):
        print(f"Block {i + 1}: {block.hash_block()}")

def main():
    print("Welcome to the Blockchain CLI!")

    sender_private_key, sender_public_key = generate_key_pair()
    blockchain = [create_genesis_block()]

    while True:
        print("\n1. Add Transaction")
        print("2. View Blockchain")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            recipient_public_key = input("Enter recipient's public key: ")
            amount = input("Enter transaction amount: ")

            try:
                amount = float(amount)
            except ValueError:
                print("Invalid amount. Please enter a valid number.")
                continue

            new_block = Block(transactions=[], previous_block_hash=blockchain[-1].hash_block())
            add_transaction_to_block(new_block, sender_private_key, recipient_public_key, amount)
            blockchain.append(new_block)
            print("Transaction added successfully!")

        elif choice == "2":
            display_blockchain(blockchain)

        elif choice == "3":
            print("Exiting the Blockchain CLI. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
