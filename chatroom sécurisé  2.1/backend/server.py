import logging
from logging.handlers import RotatingFileHandler
import os

# Function to set file permissions securely
def set_secure_file_permissions(file_path):
    # Set file permissions to read/write for the owner only
    os.chmod(file_path, 0o600)

# Create a rotating file handler
log_file = 'server.log'
handler = RotatingFileHandler(log_file, maxBytes=1000000, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Set secure permissions on the log file
set_secure_file_permissions(log_file)

# Example logging
logger.info("Logging is set up.")

# Existing imports and code...
import threading
import socket
import argparse
import os

class Server(threading.Thread):
    # Your existing Server class code...
    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        logger.info(f"Listening at {sock.getsockname()}")

        while True:
            sc, sockname = sock.accept()
            logger.info(f"Nouvelle connexion de {sc.getpeername()}")

            server_socket = ServerSocket(sc, sockname, self)
            server_socket.start()
            self.connections.append(server_socket)
            logger.info(f"En attente de message(s) de {sc.getpeername()}")

    def broadcast(self, message, source, is_file=False, filename=None, file_content=None):
        for connection in self.connections:
            if connection.sockname != source:
                connection.send(message, is_file, filename, file_content)
                if is_file:
                    logger.info(f"Broadcasting file: {filename} from {source}")
                else:
                    logger.info(f"Broadcasting message from {source}: {message}")

    def remove_connection(self, connection):
        self.connections.remove(connection)
        logger.info(f"Connection removed: {connection.sockname}")

class ServerSocket(threading.Thread):
    # Your existing ServerSocket class code...
    def run(self):
        while True:
            header = self.sc.recv(1024).decode("utf-8")
            if header.startswith("/file "):
                parts = header.split(' ', 3)
                if len(parts) < 4:
                    continue
                filename, file_size = parts[1], int(parts[2])
                file_content = self.receive_file(file_size)
                self.server.broadcast(f"/file {filename} {file_size}", self.sockname, is_file=True, filename=filename, file_content=file_content)
                logger.info(f'File received from {self.sockname}: {filename}')
            elif header:
                logger.info(f'Message received from {self.sockname}: {header}')
                print(f"Message recu de {self.sockname}: {header}")
                self.server.broadcast(header, self.sockname)
            else:
                logger.info(f'Client {self.sockname} disconnected')
                print(f"Client {self.sockname} deconnecte")
                self.sc.close()
                self.server.remove_connection(self)
                return

    def receive_file(self, file_size):
        file_content = b''
        remaining = file_size
        while remaining > 0:
            chunk_size = 1024 if remaining >= 1024 else remaining
            data = self.sc.recv(chunk_size)
            if not data:
                break
            file_content += data
            remaining -= len(data)
        return file_content

    def send(self, message, is_file=False, filename=None, file_content=None):
        if is_file:
            self.sc.sendall(message.encode("utf-8"))
            self.sc.sendall(file_content)
            logger.info(f'File sent: {filename}')
        else:
            self.sc.sendall(message.encode("utf-8"))
            logger.info(f'Message sent: {message}')

def exit(server):
    while True:
        ipt = input("")
        if ipt == "stop":
            logger.info("Arret du serveur")
            print("Arret du serveur")
            for connection in server.connections:
                connection.sc.close()

            logger.info("Fermeture du serveur")
            print("Fermeture du serveur")
            os._exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument("host", help="IP du serveur")
    parser.add_argument("-p", metavar="PORT", type=int, help="TCP port (default 1060)", default=1060)

    args = parser.parse_args()

    server = Server(args.host, args.p)
    server.start()

    exit_thread = threading.Thread(target=exit, args=(server,))
    exit_thread.start()
