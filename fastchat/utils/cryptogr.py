from base64 import b64encode, b64decode
from ecies.utils import generate_key, PrivateKey, PublicKey
from ecies import encrypt, decrypt


def load_private_key(key: str) -> PrivateKey:
    """
    Loads a private key from a string.
    :param key: The private key in string format.
    :return: The private key.
    """
    return PrivateKey(b64decode(key))


def dump_private_key(key: PrivateKey) -> str:
    """
    Dumps a private key to a string.
    :param key: The private key.
    :return: The private key in string format.
    """
    return b64encode(key.secret).decode()


def load_public_key(key: str) -> PublicKey:
    """
    Loads a public key from a string.
    :param key: The public key in string format.
    :return: The public key.
    """
    return PublicKey(b64decode(key))


def dump_public_key(key: PublicKey) -> str:
    """
    Dumps a public key to a string.
    :param key: The public key.
    :return: The public key in string format.
    """
    return b64encode(key.format(compressed=True)).decode()


def encrypt_message(message: bytes, public_key: PublicKey) -> bytes:
    """
    Encrypts a message with a public key.
    :param message: The message to encrypt.
    :param public_key: The public key to encrypt with.
    :return: The encrypted message.
    """
    return encrypt(public_key.format(True), message)


def decrypt_message(message: bytes, private_key: PrivateKey) -> bytes:
    """
    Decrypts a message with a private key.
    :param message: The message to decrypt.
    :param private_key: The private key to decrypt with.
    :return: The decrypted message.
    """
    return decrypt(private_key.secret, message)


def sign_message(message: bytes, private_key: PrivateKey) -> bytes:
    """
    Signs a message with a private key.
    :param message: The message to sign.
    :param private_key: The private key to sign with.
    :return: The signed message.
    """
    return private_key.sign(message)
