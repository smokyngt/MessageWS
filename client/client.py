import asyncio
import websockets
from cryptography.fernet import Fernet

# Utilisation de la même clé que le serveur
KEY = b'1xnLGZ7urCaxwRpsjYdPql6oe9ePrf_RPl2_yadLBwY='
cipher = Fernet(KEY)

async def send_message(websocket):
    loop = asyncio.get_running_loop()
    while True:
        msg = await loop.run_in_executor(None, input, "Entrez votre message: ")
        await websocket.send(msg)

async def receive_message(websocket):
    async for message in websocket:
        try:
            # Déchiffrement du message reçu
            decrypted = cipher.decrypt(message.encode()).decode()
            print("Message reçu (déchiffré) :", decrypted)
        except Exception as e:
            print("Erreur lors du déchiffrement du message :", message)

async def main():
    async with websockets.connect("ws://localhost:8765") as websocket:
        print("Connecté au serveur.")
        await asyncio.gather(send_message(websocket), receive_message(websocket))

if __name__ == "__main__":
    asyncio.run(main())
