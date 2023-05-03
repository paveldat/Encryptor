"""
        ██▄██ ▄▀▄ █▀▄ █▀▀ . █▀▄ █░█
        █░▀░█ █▄█ █░█ █▀▀ . █▀▄ ▀█▀
        ▀░░░▀ ▀░▀ ▀▀░ ▀▀▀ . ▀▀░ ░▀░
▒▐█▀█─░▄█▀▄─▒▐▌▒▐▌░▐█▀▀▒██░░░░▐█▀█▄─░▄█▀▄─▒█▀█▀█
▒▐█▄█░▐█▄▄▐█░▒█▒█░░▐█▀▀▒██░░░░▐█▌▐█░▐█▄▄▐█░░▒█░░
▒▐█░░░▐█─░▐█░▒▀▄▀░░▐█▄▄▒██▄▄█░▐█▄█▀░▐█─░▐█░▒▄█▄░
"""


import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import Backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncodeDecode:
    """
    Class to encode/decode text using user's password.
    """

    __backend: Backend

    def __init__(self) -> None:
        """
        Consturctor.
        """
        self.__backend = default_backend()

    @property
    def backend(self) -> Backend:
        return self.__backend

    @backend.setter
    def backend(self, value: Backend) -> None:
        self.__backend = value

    def __derive_key(self, password: bytes, salt: bytes,
                     algorithm: hashes.HashAlgorithm = hashes.SHA256(),
                     length: int = 32, iterations: int = 100_000) -> bytes:
        """
        Derive a secret key from a given password and salt.

        Args:
            * password - User's password.
            * algorithm - An instance of HashAlgorithm. Default: SHA256.
            * length - The desired length of the derived key in bytes.
                       Default: 32.
            * salt - A salt. Secure values are 128-bits (16 bytes) or
                     longer and randomly generated.
            * iterations - The number of iterations to perform of the hash
                           function. Default: 100_000.

        Returns:
            * Generated key with bytes type.
        """

        kdf = PBKDF2HMAC(
            algorithm=algorithm, length=length,
            salt=salt, iterations=iterations,
            backend=self.__backend
        )
        return b64e(kdf.derive(password))

    def encrypt(self, message: str, password: str,
                algorithm: hashes.HashAlgorithm = hashes.SHA256(),
                length: int = 32, iterations: int = 100_000) -> str:
        """
        Encrypt message.

        Args:
            * message - User's message/text.
            * password - User's password.
            * algorithm - An instance of HashAlgorithm. Default: SHA256.
            * length - The desired length of the derived key in bytes.
                       Default: 32.
            * iterations - The number of iterations to perform of the hash
                           function. Default: 100_000.

        Returns:
            * Encrypted message/text.
        """

        salt = secrets.token_bytes(16)
        key = self.__derive_key(password=password.encode(), salt=salt,
                                algorithm=algorithm, length=length,
                                iterations=iterations)
        return (
            b64e(
                b'%b%b%b' % (
                    salt,
                    iterations.to_bytes(4, 'big'),
                    b64d(Fernet(key).encrypt(message.encode()))
                )
            )
        ).decode()

    def decrypt(self, token: str, password: str,
                algorithm: hashes.HashAlgorithm = hashes.SHA256(),
                length: int = 32) -> str:
        """
        Decrypt message.

        Args:
            * token - Encrupted message.
            * password - User's password.
            * algorithm - An instance of HashAlgorithm. Default: SHA256.
            * length - The desired length of the derived key in bytes.
                       Default: 32.

        Returns:
            * Decrypted message/text.
        """

        try:
            decoded = b64d(token.encode())
            salt, iter = decoded[:16], decoded[16:20]
            token = b64e(decoded[20:])
            iterations = int.from_bytes(iter, 'big')
            key = self.__derive_key(password=password.encode(), salt=salt,
                                    algorithm=algorithm, length=length,
                                    iterations=iterations)
            return (Fernet(key).decrypt(token)).decode()
        except InvalidToken:
            print('Got invalid token or password.')
            return ''
