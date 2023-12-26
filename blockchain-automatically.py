from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime
import math
import random
from time import sleep

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
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode())
        return digest.finalize()

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

def add_transaction_to_block(block, sender_private_key, recipient_public_key, amount, transaction_history):
    sender_public_key = sender_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    recipient_public_key_bytes = recipient_public_key.encode('utf-8')

    transaction = {
        "sender": sender_public_key,
        "recipient": recipient_public_key_bytes,
        "amount": amount
    }

    signature = sign_message(sender_private_key, str(transaction))

    if not verify_signature(sender_private_key.public_key(), str(transaction), signature):
        print("Transaction signature verification failed.")
        return None

    block.transactions.append({
        "transaction": transaction,
        "signature": signature
    })

    transaction_history.append({
        "block_hash": block.hash_block(),
        "transaction": transaction,
        "signature": signature
    })

def display_blockchain(blockchain, transaction_history):
    for i, block in enumerate(blockchain):
        print(f"Block {i + 1}: Hash - {block.hash_block()}")

        for tx_data in block.transactions:
            if isinstance(tx_data, str) and tx_data == "Genesis Transaction":
                print("Genesis block detected. No transactions to display.")
            else:
                # Check if tx_data is a dictionary (transaction) or a string (genesis block)
                transaction = tx_data if isinstance(tx_data, dict) else {"transaction": tx_data, "signature": None}

                sender = transaction['transaction']['sender'].decode('utf-8')
                recipient = transaction['transaction']['recipient'].decode('utf-8')
                print(f"    Sender: {sender}")
                print(f"    Recipient: {recipient}")
                print(f"    Amount: {transaction['transaction']['amount']}")
                print(f"    Signature: {transaction['signature']}")
        print("\n")

    print("Transaction History:")
    for tx_data in transaction_history:
        transaction = tx_data['transaction']
        sender = transaction['sender'].decode('utf-8')  # Decode the bytes to a string
        recipient = transaction['recipient'].decode('utf-8')  # Decode the bytes to a string
        print(f"Block Hash: {tx_data['block_hash']}")
        print(f"    Sender: {sender}")
        print(f"    Recipient: {recipient}")
        print(f"    Amount: {transaction['amount']}")
        print(f"    Signature: {tx_data['signature']}")
        print("\n")

def automated_transactions(sender_private_key, blockchain, transaction_history):
    # Example automated transactions for demonstration purposes
    recipients = ["Recipient1", "Recipient2", "Recipient3"]
    for recipient in recipients:
        amount = random.uniform(1, 10)
        new_block = Block(transactions=[], previous_block_hash=blockchain[-1].hash_block())
        recipient_public_key = f"RecipientPublicKey_{recipient}"
        add_transaction_to_block(new_block, sender_private_key, recipient_public_key, amount, transaction_history)
        blockchain.append(new_block)
        print(f"Transaction to {recipient} added successfully!")
        sleep(1)  # Adding a delay for better visualization

def main():
    print("Welcome to the Blockchain CLI!")

    sender_private_key, sender_public_key = generate_key_pair()
    blockchain = [create_genesis_block()]
    transaction_history = []

    # Execute automated transactions
    automated_transactions(sender_private_key, blockchain, transaction_history)

    # Display Blockchain and Transaction History
    display_blockchain(blockchain, transaction_history)

    print("Exiting the Blockchain CLI. Goodbye!")

if __name__ == "__main__":
    main()