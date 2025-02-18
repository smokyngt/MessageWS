import asyncio
import websockets
from cryptography.fernet import Fernet
import subprocess

# Clé fixe pour la démonstration (générée par Fernet.generate_key())
KEY = b'1xnLGZ7urCaxwRpsjYdPql6oe9ePrf_RPl2_yadLBwY='
cipher = Fernet(KEY)

# Ensemble des clients connectés
connected = set()

async def handler(websocket, path=None):
    connected.add(websocket)
    try:
        async for message in websocket:
            print("Message reçu (clair) :", message)
            # Chiffrement du message
            encrypted = cipher.encrypt(message.encode()).decode()
            print("Message chiffré :", encrypted)
            # Envoi à tous les autres clients
            for conn in connected:
                if conn != websocket:
                    await conn.send(encrypted)
    finally:
        connected.remove(websocket)

    connected.add(websocket)
    try:
        async for message in websocket:
            capture_cmd = ["tshark", "-i", "Wi-Fi", "-f", "tcp port 8765", "-w", "capture.pcap"]
            capture_process = subprocess.Popen(capture_cmd)
            print("Message reçu (clair) :", message)
            # Chiffrement du message
            encrypted = cipher.encrypt(message.encode()).decode()
            print("Message chiffré :", encrypted)
            # Envoi à tous les autres clients
            for conn in connected:
                if conn != websocket:
                    await conn.send(encrypted)
    finally:
        connected.remove(websocket)

async def main():
    server = await websockets.serve(handler, "localhost", 8765)
    print("Serveur démarré sur ws://localhost:8765")
    await server.wait_closed()
    

if __name__ == "__main__":
    asyncio.run(main())
