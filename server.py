import asyncio
import websockets
import json
from cipher import Cipher  # Assurez-vous que cipher.py est accessible depuis ce script

# --- Menu interactif pour choisir l'algorithme ---

def choose_cipher():
    print("Choisissez l'algorithme de chiffrement :")
    print("1) Caesar")
    print("2) Vigenere")
    print("3) AES (Fernet)")
    print("4) RSA")
    choice = input("Entrez le numéro correspondant (1-4) : ").strip()

    if choice == "1":
        # Pour César, le décalage est fixé à 3 (comme demandé)
        return "caesar", Cipher(algo="caesar", shift=3)
    elif choice == "2":
        # Pour Vigenère, on génère automatiquement une clé aléatoire de 8 lettres majuscules
        import random, string
        random_key = ''.join(random.choices(string.ascii_uppercase, k=8))
        print(f"Clé Vigenère générée automatiquement : {random_key}")
        return "vigenere", Cipher(algo="vigenere", key=random_key)
    elif choice == "3":
        # Pour AES (Fernet), la clé est générée automatiquement
        return "aes", Cipher(algo="aes")
    elif choice == "4":
        # Pour RSA, une paire de clés est générée automatiquement
        return "rsa", Cipher(algo="rsa")
    else:
        print("Choix invalide. Utilisation par défaut de Caesar avec shift=3.")
        return "caesar", Cipher(algo="caesar", shift=3)

# Choix interactif au lancement du serveur
ALGO, cipher = choose_cipher()

# Préparation d'un message de configuration à envoyer aux clients
# On envoie les paramètres nécessaires pour qu'ils puissent configurer leur Cipher identique.
config = {"algo": ALGO}
if ALGO == "caesar":
    config["shift"] = 3
elif ALGO == "vigenere":
    # Pour Vigenère, on transmet la clé générée
    config["key"] = cipher.key
elif ALGO == "aes":
    # Pour AES, on transmet la clé Fernet en chaîne (décodée en UTF-8)
    config["key"] = cipher.aes_key.decode()
elif ALGO == "rsa":
    # Pour RSA, on transmet la clé privée en PEM (pour la décryption côté client, à titre pédagogique)
    from cryptography.hazmat.primitives import serialization
    private_pem = cipher.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    config["private_key"] = private_pem

# Ensemble des clients connectés
connected = set()

async def handler(websocket, path=None):
    connected.add(websocket)
    try:
        # Dès la connexion, le serveur envoie la configuration au client
        await websocket.send(json.dumps(config))
        async for message in websocket:
            print("Message reçu (en clair) :", message)
            # Chiffrement du message avant diffusion
            encrypted = cipher.encrypt(message)
            print(f"Message chiffré ({ALGO}) :", encrypted)
            # Envoi du message chiffré aux autres clients (pas à l'expéditeur)
            for client_ws in connected:
                if client_ws != websocket:
                    await client_ws.send(encrypted)
    finally:
        connected.remove(websocket)

async def main():
    async with websockets.serve(handler, "localhost", 8765):
        print("Serveur démarré sur ws://localhost:8765")
        print(f"Algorithme utilisé : {ALGO.upper()}")
        await asyncio.Future()  # Pour maintenir le serveur actif

if __name__ == "__main__":
    asyncio.run(main())
