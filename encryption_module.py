"""
Advanced Encryption Module
Multiple Encryption Techniques for Steganography
# added by naveen on 01-feb_2025
"""

import os
import base64
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# added by naveen on 15-feb_2025
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import json
import struct
import time

class AdvancedEncryption:
    """Advanced Encryption Class with Multiple Algorithms"""

    def __init__(self):
        self.backend = default_backend()
        # added by naveen on 28-feb_2025
        self.salt_length = 16
        self.iv_length = 16
        self.key_length = 32  # 256-bit keys

    def generate_salt(self, length=None):
        """Generate cryptographically secure salt"""
        if length is None:
            length = self.salt_length
        return secrets.token_bytes(length)

    def generate_iv(self, length=None):
        """Generate initialization vector"""
        if length is None:
            length = self.iv_length
        # added by naveen on 12-mar_2025
        return secrets.token_bytes(length)

    def derive_key_pbkdf2(self, password, salt, iterations=100000):
        """Derive key using PBKDF2"""
        try:
            if isinstance(password, str):
                password = password.encode('utf-8')

            # added by naveen on 25-mar_2025
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=iterations,
                backend=self.backend
            )
            return kdf.derive(password)

        except Exception as e:
            raise ValueError(f"Key derivation failed: {str(e)}")

    def fernet_encrypt(self, data, password):
        """Encrypt data using Fernet (AES-128 in CBC mode)"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            # added by naveen on 10-apr_2025
            # Generate salt
            salt = self.generate_salt()

            # Derive key
            key = self.derive_key_pbkdf2(password, salt)
            key_b64 = base64.urlsafe_b64encode(key)

            # Create Fernet instance
            fernet = Fernet(key_b64)

            # Encrypt data
            encrypted_data = fernet.encrypt(data)

            # added by naveen on 20-apr_2025
            # Combine salt and encrypted data
            result = salt + encrypted_data

            return base64.b64encode(result).decode('utf-8')

        except Exception as e:
            raise ValueError(f"Fernet encryption failed: {str(e)}")

    def fernet_decrypt(self, encrypted_data, password):
        """Decrypt data using Fernet"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))

            # added by naveen on 05-may_2025
            # Extract salt and encrypted data
            salt = encrypted_bytes[:self.salt_length]
            encrypted_data = encrypted_bytes[self.salt_length:]

            # Derive key
            key = self.derive_key_pbkdf2(password, salt)
            key_b64 = base64.urlsafe_b64encode(key)

            # Create Fernet instance
            fernet = Fernet(key_b64)

            # added by naveen on 18-may_2025
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)

            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted_data

        except Exception as e:
            raise ValueError(f"Fernet decryption failed: {str(e)}")

    def aes_encrypt(self, data, password, mode='CBC'):
        """Encrypt data using AES with specified mode"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            # added by naveen on 30-may_2025
            # Generate salt and IV
            salt = self.generate_salt()
            iv = self.generate_iv()

            # Derive key
            key = self.derive_key_pbkdf2(password, salt)

            # Pad data to block size (16 bytes for AES)
            pad_length = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_length] * pad_length)

            # added by naveen on 10-jun_2025
            # Create cipher
            if mode.upper() == 'CBC':
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=self.backend
                )
            elif mode.upper() == 'GCM':
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv),
                    backend=self.backend
                )
            else:
                raise ValueError(f"Unsupported mode: {mode}")

            encryptor = cipher.encryptor()

            # added by naveen on 20-jun_2025
            # Encrypt data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # For GCM mode, get authentication tag
            if mode.upper() == 'GCM':
                tag = encryptor.tag
                result = salt + iv + tag + encrypted_data
            else:
                result = salt + iv + encrypted_data

            return base64.b64encode(result).decode('utf-8')

        except Exception as e:
            raise ValueError(f"AES encryption failed: {str(e)}")

    def aes_decrypt(self, encrypted_data, password, mode='CBC'):
        """Decrypt data using AES"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))

            # added by naveen on 30-jun_2025
            # Extract components
            salt = encrypted_bytes[:self.salt_length]
            iv = encrypted_bytes[self.salt_length:self.salt_length + self.iv_length]

            if mode.upper() == 'GCM':
                tag = encrypted_bytes[self.salt_length + self.iv_length:self.salt_length + self.iv_length + 16]
                encrypted_data = encrypted_bytes[self.salt_length + self.iv_length + 16:]
            else:
                encrypted_data = encrypted_bytes[self.salt_length + self.iv_length:]

            # Derive key
            key = self.derive_key_pbkdf2(password, salt)

            # added by naveen on 15-jul_2025
            # Create cipher
            if mode.upper() == 'CBC':
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=self.backend
                )
            elif mode.upper() == 'GCM':
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, tag),
                    backend=self.backend
                )
            else:
                raise ValueError(f"Unsupported mode: {mode}")

            decryptor = cipher.decryptor()

            # added by naveen on 30-jul_2025
            # Decrypt data
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            if mode.upper() == 'CBC':
                pad_length = decrypted_data[-1]
                decrypted_data = decrypted_data[:-pad_length]

            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted_data

        except Exception as e:
            raise ValueError(f"AES decryption failed: {str(e)}")

# added by naveen on 15-aug_2025
class RSAEncryption:
    """RSA Encryption for key exchange and digital signatures"""

    def __init__(self):
        self.key_size = 2048

    def generate_key_pair(self):
        """Generate RSA key pair"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.key_size,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # added by naveen on 30-aug_2025
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return private_pem, public_pem

        except Exception as e:
            raise ValueError(f"RSA key generation failed: {str(e)}")

    def encrypt_rsa(self, data, public_key_pem):
        """Encrypt data using RSA public key"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            # added by naveen on 15-sep_2025
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )

            # Encrypt data
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            return base64.b64encode(encrypted_data).decode('utf-8')

        except Exception as e:
            raise ValueError(f"RSA encryption failed: {str(e)}")

    def decrypt_rsa(self, encrypted_data, private_key_pem):
        """Decrypt data using RSA private key"""
        try:
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))

            # added by naveen on 30-sep_2025
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )

            # Decrypt data
            decrypted_data = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted_data

        except Exception as e:
            raise ValueError(f"RSA decryption failed: {str(e)}")

# added by naveen on 15-oct_2025
class HybridEncryption:
    """Hybrid encryption combining RSA and AES"""

    def __init__(self):
        self.aes = AdvancedEncryption()
        self.rsa = RSAEncryption()

    def encrypt_hybrid(self, data, public_key_pem):
        """Encrypt data using hybrid approach"""
        try:
            # Generate random AES key
            aes_key = secrets.token_bytes(32)

            # added by naveen on 30-oct_2025
            # Encrypt data with AES
            if isinstance(data, str):
                data = data.encode('utf-8')

            # Generate IV and salt
            iv = self.aes.generate_iv()
            salt = self.aes.generate_salt()

            # Encrypt with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )

            # added by naveen on 15-nov_2025
            # Pad data
            pad_length = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_length] * pad_length)

            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Encrypt AES key with RSA
            encrypted_key = self.rsa.encrypt_rsa(aes_key, public_key_pem)

            # added by naveen on 30-nov_2025
            # Combine all components
            result = {
                'encrypted_key': encrypted_key,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')
            }

            return json.dumps(result)

        except Exception as e:
            raise ValueError(f"Hybrid encryption failed: {str(e)}")

    def decrypt_hybrid(self, encrypted_json, private_key_pem):
        """Decrypt data using hybrid approach"""
        try:
            # Parse JSON
            data = json.loads(encrypted_json)

            # added by naveen on 15-dec_2025
            # Decrypt AES key with RSA
            aes_key = self.rsa.decrypt_rsa(data['encrypted_key'], private_key_pem)

            # Decode components
            salt = base64.b64decode(data['salt'])
            iv = base64.b64decode(data['iv'])
            encrypted_data = base64.b64decode(data['encrypted_data'])

            # Decrypt with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )

            # added by naveen on 30-dec_2025
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            # Remove padding
            pad_length = decrypted_data[-1]
            decrypted_data = decrypted_data[:-pad_length]

            try:
                return decrypted_data.decode('utf-8')
            except UnicodeDecodeError:
                return decrypted_data

        except Exception as e:
            raise ValueError(f"Hybrid decryption failed: {str(e)}")

# added by naveen on 15-jan_2026
class HashingUtils:
    """Utility functions for hashing and integrity verification"""

    @staticmethod
    def calculate_hash(data, algorithm='SHA256'):
        """Calculate hash of data"""
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')

            if algorithm.upper() == 'SHA256':
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            elif algorithm.upper() == 'SHA512':
                digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
            elif algorithm.upper() == 'MD5':
                digest = hashes.Hash(hashes.MD5(), backend=default_backend())
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            digest.update(data)
            return digest.finalize().hex()

        except Exception as e:
            raise ValueError(f"Hash calculation failed: {str(e)}")

    @staticmethod
    def verify_hash(data, expected_hash, algorithm='SHA256'):
        """Verify data integrity using hash"""
        try:
            calculated_hash = HashingUtils.calculate_hash(data, algorithm)
            return calculated_hash.lower() == expected_hash.lower()

        except Exception as e:
            raise ValueError(f"Hash verification failed: {str(e)}")

# added by naveen on 30-jan_2026
