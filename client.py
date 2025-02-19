import asyncio
import websockets
import json
from cipher import Cipher  # Assurez-vous que cipher.py est accessible

# Pour RSA, il faut importer la sérialisation
from cryptography.hazmat.primitives import serialization

async def send_message(websocket):
    loop = asyncio.get_running_loop()
    while True:
        msg = await loop.run_in_executor(None, input, "Entrez votre message: ")
        await websocket.send(msg)

async def receive_message(websocket, cipher):
    async for message in websocket:
        # Si le message reçu est une configuration, on l'ignore (il a déjà été traité)
        # Sinon, on le déchiffre et on l'affiche.
        try:
            decrypted = cipher.decrypt(message)
            print("\nMessage reçu (déchiffré) :", decrypted)
        except Exception as e:
            print("\nErreur lors du déchiffrement :", e)
            print("Message brut reçu :", message)

async def main():
    async with websockets.connect("ws://localhost:8765") as websocket:
        # Récupère la configuration envoyée par le serveur
        config_msg = await websocket.recv()
        config = json.loads(config_msg)
        algo = config.get("algo")
        print(f"Configuration reçue : {algo}")
        # Instanciation du Cipher côté client en fonction de la configuration reçue
        if algo == "caesar":
            shift = config.get("shift", 3)
            cipher = Cipher(algo="caesar", shift=shift)
        elif algo == "vigenere":
            key = config.get("key")
            cipher = Cipher(algo="vigenere", key=key)
        elif algo == "aes":
            key = config.get("key").encode()  # on retransforme en bytes
            cipher = Cipher(algo="aes", key=key)
        elif algo == "rsa":
            private_pem = config.get("private_key").encode()
            cipher = Cipher(algo="rsa", rsa_private_key=private_pem)
        else:
            raise ValueError("Algorithme inconnu dans la configuration reçue.")

        print(f"Algorithme configuré côté client : {algo.upper()}")
        # Lancement simultané de l'envoi et de la réception
        await asyncio.gather(send_message(websocket), receive_message(websocket, cipher))

if __name__ == "__main__":
    asyncio.run(main())
