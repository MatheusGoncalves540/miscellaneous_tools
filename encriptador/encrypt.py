from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


def encrypt(message: str, password: str) -> str:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )

    key = kdf.derive(password.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()

    return base64.urlsafe_b64encode(iv + salt + encryptor.tag + ct).decode()


if __name__ == "__main__":
    message = input("Digite a mensagem que deseja criptografar: ")
    password = input("Digite a chave para criptografar a mensagem: ")
    encrypted_message = encrypt(message, password)
    print(f"Mensagem criptografada: {encrypted_message}")
    input()
