from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import datetime

class Block:
    def __init__(self, transactions, previous_block_hash=None):
        self.transactions = transactions
        self.previous_block_hash = previous_block_hash  # Store hash, not the entire block
        self.timestamp = datetime.datetime.now()
        self.nonce = 0

    def hash_block(self):
        transaction_str = ",".join(str(tx) for tx in self.transactions)
        block_str = f"{transaction_str}{self.previous_block_hash}{self.timestamp}{self.nonce}"

        # Store the hash object and return its finalization
        hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_obj.update(block_str.encode())
        return hash_obj.finalize()  # Return the finalized hash

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    # Encode the message before signing
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
    try:
        # Encode the message before verification
        message_bytes = message.encode('utf-8')

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
    # Create a genesis block with some initial transactions
    return Block(transactions=["Genesis Transaction"])

def add_transaction_to_block(block, sender_private_key, recipient_public_key, amount):
    # Create a transaction and sign it
    transaction = {
        # Use sender's public key
        "sender": sender_private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),
        "recipient": recipient_public_key,
        "amount": amount
    }
    signature = sign_message(sender_private_key, str(transaction))

    # Verify the signature
    if not verify_signature(recipient_public_key, str(transaction), signature):
        print("Transaction signature verification failed.")
        return None

    # Add the signed transaction to the block
    block.transactions.append({
        "transaction": transaction,
        "signature": signature
    })

def main():
    # Generate key pair for a participant (replace this with multiple participants/nodes)
    sender_private_key, sender_public_key = generate_key_pair()

    # Create a blockchain with a genesis block
    blockchain = [create_genesis_block()]

    # Create a new block and add a transaction
    new_block = Block(transactions=["Initial Transaction"], previous_block_hash=blockchain[-1].hash_block())
    add_transaction_to_block(new_block, sender_private_key, sender_public_key, 10)

    # Add the new block to the blockchain
    blockchain.append(new_block)

    # Print the blockchain
    for i, block in enumerate(blockchain):
        print(f"Block {i + 1}: {block.hash_block()}")

if __name__ == "__main__":
    main()
