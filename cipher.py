import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization

class Cipher:
    def __init__(self, algo="caesar", shift=3, key=None, rsa_private_key=None, rsa_public_key=None):
        """
        Initialise la classe Cipher.

        :param algo: "caesar", "vigenere", "aes" ou "rsa"
        :param shift: Le décalage pour l'algorithme de César.
        :param key: Pour Vigenère, la clé sous forme de chaîne.
                    Pour AES, la clé Fernet (si None, une clé sera générée).
        :param rsa_private_key: Clé privée RSA (objet ou en PEM) pour RSA.
        :param rsa_public_key: Clé publique RSA (objet ou en PEM) pour RSA.
        """
        self.algo = algo.lower()
        self.shift = shift
        
        if self.algo == "vigenere":
            if key is None:
                raise ValueError("Pour Vigenère, une clé doit être fournie.")
            self.key = key.upper()
            
        elif self.algo == "aes":
            # Pour AES, on utilisera Fernet qui repose sur AES en mode CBC avec HMAC
            if key is None:
                key = Fernet.generate_key()
            self.aes_key = key  # clé binaire (bytes)
            self.fernet = Fernet(self.aes_key)
            
        elif self.algo == "rsa":
            # Pour RSA, on nécessite une paire de clés.
            # Si aucune clé n'est fournie, on génère une paire de clés.
            if rsa_private_key is None and rsa_public_key is None:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                self.public_key = self.private_key.public_key()
            else:
                # Si on fournit au moins la clé privée, on la charge.
                if rsa_private_key is not None:
                    if isinstance(rsa_private_key, bytes):
                        self.private_key = serialization.load_pem_private_key(
                            rsa_private_key,
                            password=None,
                        )
                    else:
                        self.private_key = rsa_private_key
                    self.public_key = self.private_key.public_key()
                elif rsa_public_key is not None:
                    if isinstance(rsa_public_key, bytes):
                        self.public_key = serialization.load_pem_public_key(rsa_public_key)
                    else:
                        self.public_key = rsa_public_key
                    self.private_key = None  # en mode chiffrement asymétrique, seule la clé publique est nécessaire pour chiffrer
        else:
            # Pour "caesar" ou autre, pas de paramètre supplémentaire requis.
            pass

    def encrypt(self, plaintext):
        """
        Chiffre le texte en fonction de l'algorithme sélectionné.
        Pour César et Vigenère, le texte sera converti en majuscules.
        Pour AES et RSA, le texte est encodé en bytes.
        """
        if self.algo == "caesar":
            return self._encrypt_caesar(plaintext.upper(), self.shift)
        elif self.algo == "vigenere":
            return self._encrypt_vigenere(plaintext.upper(), self.key)
        elif self.algo == "aes":
            # Fernet s'attend à des bytes
            token = self.fernet.encrypt(plaintext.encode())
            # On renvoie une chaîne en base64 pour faciliter l'affichage
            return token.decode()
        elif self.algo == "rsa":
            if not self.public_key:
                raise ValueError("Clé publique RSA non définie.")
            ciphertext = self.public_key.encrypt(
                plaintext.encode(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # On encode en base64 pour obtenir une chaîne
            return base64.b64encode(ciphertext).decode()
        else:
            raise ValueError("Algorithme non supporté.")

    def decrypt(self, ciphertext):
        """
        Déchiffre le texte en fonction de l'algorithme sélectionné.
        Pour RSA, la clé privée doit être disponible.
        """
        if self.algo == "caesar":
            return self._decrypt_caesar(ciphertext.upper(), self.shift)
        elif self.algo == "vigenere":
            return self._decrypt_vigenere(ciphertext.upper(), self.key)
        elif self.algo == "aes":
            # Fernet renvoie des bytes, que l'on décode ensuite
            decrypted = self.fernet.decrypt(ciphertext.encode())
            return decrypted.decode()
        elif self.algo == "rsa":
            if not self.private_key:
                raise ValueError("Clé privée RSA non définie, impossible de déchiffrer.")
            # Décodage base64 avant décryptage
            raw_ciphertext = base64.b64decode(ciphertext.encode())
            plaintext = self.private_key.decrypt(
                raw_ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        else:
            raise ValueError("Algorithme non supporté.")

    # Méthodes internes pour César
    def _encrypt_caesar(self, plaintext, shift):
        result = ""
        for char in plaintext:
            if 'A' <= char <= 'Z':
                index = ord(char) - ord('A')
                shifted_index = (index + shift) % 26
                result += chr(shifted_index + ord('A'))
            else:
                result += char
        return result

    def _decrypt_caesar(self, ciphertext, shift):
        result = ""
        for char in ciphertext:
            if 'A' <= char <= 'Z':
                index = ord(char) - ord('A')
                shifted_index = (index - shift) % 26
                result += chr(shifted_index + ord('A'))
            else:
                result += char
        return result

    # Méthodes internes pour Vigenère
    def _encrypt_vigenere(self, plaintext, key):
        result = ""
        key_length = len(key)
        key_index = 0
        for char in plaintext:
            if 'A' <= char <= 'Z':
                shift = ord(key[key_index % key_length]) - ord('A')
                index = ord(char) - ord('A')
                shifted_index = (index + shift) % 26
                result += chr(shifted_index + ord('A'))
                key_index += 1
            else:
                result += char
        return result

    def _decrypt_vigenere(self, ciphertext, key):
        result = ""
        key_length = len(key)
        key_index = 0
        for char in ciphertext:
            if 'A' <= char <= 'Z':
                shift = ord(key[key_index % key_length]) - ord('A')
                index = ord(char) - ord('A')
                shifted_index = (index - shift) % 26
                result += chr(shifted_index + ord('A'))
                key_index += 1
            else:
                result += char
        return result

# Exemple d'utilisation de la classe Cipher
if __name__ == "__main__":
    message = "Bonjour à tous!"

    # Exemple avec César
    cipher_caesar = Cipher(algo="caesar", shift=3)
    encrypted_caesar = cipher_caesar.encrypt(message)
    decrypted_caesar = cipher_caesar.decrypt(encrypted_caesar)
    print("César")
    print("Original :", message)
    print("Chiffré :", encrypted_caesar)
    print("Déchiffré :", decrypted_caesar)
    print()

    # Exemple avec Vigenère
    cipher_vigenere = Cipher(algo="vigenere", key="CLE")
    encrypted_vigenere = cipher_vigenere.encrypt(message)
    decrypted_vigenere = cipher_vigenere.decrypt(encrypted_vigenere)
    print("Vigenère")
    print("Original :", message)
    print("Chiffré :", encrypted_vigenere)
    print("Déchiffré :", decrypted_vigenere)
    print()

    # Exemple avec AES (via Fernet)
    cipher_aes = Cipher(algo="aes")
    encrypted_aes = cipher_aes.encrypt(message)
    decrypted_aes = cipher_aes.decrypt(encrypted_aes)
    print("AES")
    print("Original :", message)
    print("Chiffré :", encrypted_aes)
    print("Déchiffré :", decrypted_aes)
    print()

    # Exemple avec RSA
    # Pour RSA, on génère automatiquement une paire de clés si aucune n'est fournie.
    cipher_rsa = Cipher(algo="rsa")
    encrypted_rsa = cipher_rsa.encrypt(message)
    decrypted_rsa = cipher_rsa.decrypt(encrypted_rsa)
    print("RSA")
    print("Original :", message)
    print("Chiffré :", encrypted_rsa)
    print("Déchiffré :", decrypted_rsa)
