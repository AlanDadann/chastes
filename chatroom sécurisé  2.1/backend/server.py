import threading
import socket
import argparse
import os
import logging

# Configure logging
logging.basicConfig(filename='server.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        print("Listening at", sock.getsockname())

        while True:
            sc, sockname = sock.accept()
            print(f"Nouvelle connexion de {sc.getpeername()}")

            server_socket = ServerSocket(sc, sockname, self)
            server_socket.start()
            self.connections.append(server_socket)
            print("En attente de message(s) de", sc.getpeername())

    def broadcast(self, message, source, is_file=False, filename=None, file_content=None):
        for connection in self.connections:
            if connection.sockname != source:
                connection.send(message, is_file, filename, file_content)

    def remove_connection(self, connection):
        self.connections.remove(connection)

class ServerSocket(threading.Thread):
    def __init__(self, sc, sockname, server):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server

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
                logging.info(f'File received from {self.sockname}: {filename}')
            elif header:
                logging.info(f'Message received from {self.sockname}: {header}')
                print(f"Message recu de {self.sockname}: {header}")
                self.server.broadcast(header, self.sockname)
            else:
                logging.info(f'Client {self.sockname} disconnected')
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
            logging.info(f'File sent: {filename}')
        else:
            self.sc.sendall(message.encode("utf-8"))
            logging.info(f'Message sent: {message}')


def exit(server):
    while True:
        ipt = input("")
        if ipt == "stop":
            print("Arret du serveur")
            for connection in server.connections:
                connection.sc.close()

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
