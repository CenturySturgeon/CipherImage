from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from stegano import lsb
import base64
import os

def generate_key(main_password: str) -> bytes:
    """
    Generates a key using the provided password string and salt.
    """
    password = main_password.encode()
    salt = b'salt_'  # Change this to a unique salt value
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Encrypt a password using the generated key
def encrypt_password(key: bytes, password: str) -> bytes:
    """
    Encrypts the given password using the provided key.
    """
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt a password using the generated key
def decrypt_password(key: bytes, encrypted_password: bytes) -> str:
    """
    Encrypts the given encrypted password using the provided key.
    """
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password)
    return decrypted_password.decode()

# Encrypt the password using the main password and image
def embed_encrypted_password_in_image(main_password: str, password_to_encrypt: str, image_path: str, output_path: str) -> None:
    """
    Encrypts the provided password and embeds it in an image using steganography.
    """
    key = generate_key(main_password)
    encrypted_password = encrypt_password(key, password_to_encrypt)

    # Embed the key into the image using steganography
    secret_image = lsb.hide(image_path, encrypted_password.decode())
    # Get the image name and extension
    image_name = os.path.basename(image_path)
    secret_image.save(output_path + image_name)

# Decrypt the password using the main password and image
def decrypt_password_with_image(main_password: str, encrypted_image_path: str) -> str:
    """
    Decrypts an encrypted password hiding in an image.
    """
    # Extract the encrypted password from the image using steganography
    encrypted_password = lsb.reveal(encrypted_image_path)

    key = generate_key(main_password)
    
    # Decrypt the password using the extracted key
    decrypted_password = decrypt_password(key, encrypted_password.encode())
    return decrypted_password
    