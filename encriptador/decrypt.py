from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

def decrypt(encrypted_message: str, password: str) -> str:
    data = base64.urlsafe_b64decode(encrypted_message.encode())

    iv = data[:12]
    salt = data[12:28]
    tag = data[28:44]
    ct = data[44:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )

    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_data.decode()


if __name__ == "__main__":
    encrypted_message = input("Digite a mensagem criptografada: ")
    password = input("Digite a chave para descriptografar a mensagem: ")

    try:
        decrypted_message = decrypt(encrypted_message, password)
        print(f"Mensagem descriptografada: {decrypted_message}")
        input()
    except Exception as e:
        print("Não foi possível descriptografar a mensagem. Verifique se a chave está correta.")
        input()