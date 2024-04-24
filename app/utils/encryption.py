from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import hashlib

def generate_derived_key_from_passwd(password):
    """
    Generate a derived key from the provided password.

    Args:
        password (str): The password to derive the key from.

    Returns:
        bytes: The derived key.

    """
    if isinstance(password, str):
        password = password.encode()
    # Derive a key from the provided password
    salt = b'salt_123'  # Salt for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key size is 32 bytes
        salt=salt,
        iterations=100000,  # Number of iterations for key derivation
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Function to hash the derived key using SHA256
def hash_derived_key(derived_key):
    """
    Hash the derived key using SHA256.

    Args:
        derived_key (bytes): The derived key to be hashed.

    Returns:
        str: The hashed value of the derived key.
    """
    hasher = hashlib.sha256()
    hasher.update(derived_key)
    hashed_value = hasher.hexdigest()
    return hashed_value

def encrypt_user_private_key(user_private_key, derived_key):
    """
    Encrypts a user's private key using a derived key.

    Args:
        user_private_key (str): The user's private key to be encrypted.
        derived_key (bytes): The derived key to be used for encryption.

    Returns:
        bytes: The encrypted private key.

    """
    if isinstance(user_private_key, str):
        user_private_key = user_private_key.encode()

    # Create a Fernet cipher instance with the key
    cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))

    # Encrypt the data
    encrypted_data = cipher_suite.encrypt(user_private_key)
    return encrypted_data

def decrypt_user_private_key(encrypted_private_key, derived_key):
    """
    Decrypts a user's private key using a derived key.

    Args:
        encrypted_private_key (bytes): The encrypted private key to be decrypted.
        derived_key (bytes): The derived key to be used for decryption.

    Returns:
        str: The decrypted private key.

    """
    # Create a Fernet cipher instance with the key
    cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))

    # Decrypt the data
    decrypted_data = cipher_suite.decrypt(encrypted_private_key).decode()
    return decrypted_data


def encrypt(data:str, key):
    return Fernet(key).encrypt(data.encode()).decode() if data else None

def decrypt(encrypted_data:str, key):
    return Fernet(key).decrypt(encrypted_data).decode() if encrypted_data else None


def main():
    password = "user_password"

    # Step 1: Generate Key from user's password and store this in session
    derived_key = generate_derived_key_from_passwd(password)
    print(derived_key)

    # Step 2: Generate a user private key using Fernet and save it to User db
    user_key = Fernet.generate_key()
    print(user_key)

    # Step 3: Encrypt data
    encrypted_private_key = encrypt_user_private_key(user_key, derived_key)

    # # Step 4: Decrypt the user's encrypted private key stored in the db
    user_private_key = decrypt_user_private_key(encrypted_private_key, derived_key)
    print("Decrypted data:", user_private_key)


if __name__ == '__main__':
    main()
    