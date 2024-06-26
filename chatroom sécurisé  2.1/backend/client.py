import socket
import threading
import sys
import os
import tkinter as tk
import argparse
import sqlite3
import hashlib

def create_database():
    conn = sqlite3.connect('chat_clients.db')
    cursor = conn.cursor()
    
    # Créer une table pour les clients avec des champs supplémentaires
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            gender TEXT,
            dob DATE
        )
    ''')
    
    conn.commit()
    conn.close()



class Send(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        while True:
            print('{}: '.format(self.name), end='')
            sys.stdout.flush()
            message = sys.stdin.readline().strip()

            if message == 'QUIT':
                self.sock.sendall('Server: {} a quitté(e) le chat.'.format(self.name).encode('utf-8'))
                break
            else:
                self.sock.sendall('{}: {}'.format(self.name, message).encode('utf-8'))
        
        print('\nFermeture...')
        self.sock.close()
        os._exit(0)

class Receive(threading.Thread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        while True:
            message = self.sock.recv(1024).decode('ascii')
            if message:
                print('\r{}\n{}: '.format(message, self.name), end='')
            else:
                print('\nLa connexion au serveur a été perdue\n')
                print('Fermeture...')
                self.sock.close()
                os._exit(0)

import re
from datetime import datetime

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.password = None
        self.messages = None
        
    def start(self):
        print('Tentative de connexion au serveur {}:{}'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))

        print('Connecté au serveur {}:{}'.format(self.host, self.port))

        self.name = input('Votre nom: ')
        self.password = input('Votre mot de passe: ')

        # Vérifier si l'utilisateur existe déjà
        user_exists, user_data = self.check_user_exists(self.name)

        if user_exists:
            hashed_password = user_data[2]
            if self.verify_password(self.password, hashed_password):
                print('Connexion réussie, bienvenue {}!'.format(self.name))
            else:
                print('Mot de passe incorrect. Fermeture de la connexion...')
                self.exit()
        else:
            print('Nouvel utilisateur détecté. Veuillez fournir les informations supplémentaires.')
            email = input('Adresse email: ')
            gender = input('Genre: ')
            dob = input('Date de naissance (DD-MM-YYYY): ')

            if not self.validate_dob(dob):
                print('Date de naissance invalide. Fermeture de la connexion...')
                self.exit()

            # Hasher le mot de passe avant de l'enregistrer
            hashed_password = self.hash_password(self.password)

            self.register_client(self.name, hashed_password, email, gender, dob)
            print('Inscription réussie, bienvenue {}!'.format(self.name))

        receive = Receive(self.sock, self.name)
        receive.start()

        self.sock.sendall('Server: {} a rejoint le chat. Bienvenue!'.format(self.name).encode('ascii'))

        print("\rTapez 'QUIT' pour quitter")
        print('{}:' .format(self.name), end = '')
        return receive

    def check_user_exists(self, name):
        conn = sqlite3.connect('chat_clients.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM clients WHERE name = ?', (name,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            return True, user_data
        else:
            return False, None

    def register_client(self, name, password, email, gender, dob):
        conn = sqlite3.connect('chat_clients.db')
        cursor = conn.cursor()

        cursor.execute('INSERT INTO clients (name, password, email, gender, dob) VALUES (?, ?, ?, ?, ?)', 
                    (name, password, email, gender, dob))
        
        conn.commit()
        conn.close()

    def hash_password(self, password):
        # Utilisation de SHA-256 pour le hachage du mot de passe
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def verify_password(self, password, hashed_password):
        # Vérifier si le mot de passe saisi correspond au hachage stocké
        return hashed_password == self.hash_password(password)


    def validate_dob(self, dob):
        try:
            dob_date = datetime.strptime(dob, '%d-%m-%Y')
            if dob_date < datetime.strptime('01-01-2007', '%d-%m-%Y'):
                return True
            else:
                return False
        except ValueError:
            return False

    def send(self, textInput):
        messages = textInput.get()
        textInput.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, messages))

        # Type 'QUIT' to leave the chatroom
        if messages == 'QUIT':
            self.sock.sendall('Server: {} a quitté(e) le chat.'.format(self.name).encode('utf-8'))
            print('\nFermeture...')
            self.sock.close()
            os._exit(0)
    
        else:
            self.sock.sendall('{}: {}'.format(self.name, messages).encode('ascii'))
    
    
    def exit(self, textInput):
        messages = textInput.get()
        textInput.delete(0, tk.END)
        self, messages.insert(tk.END, '{}:{}' .format(self.name, messages))

        # Type 'QUIT' to leave the chatroom
        if messages == 'QUIT':
            self.sock.sendall('Server: {} a quitté(e) le chat.'.format(self.name).encode('ascii'))

            print('\nFermeture...')
            self.sock.close()
            os._exit(0)

        # Send messages to server for broadcasting
        else:
            self.sock.sendall('{}: {}'.format(self.name, messages).encode('ascii'))

def main(host, port):
    #initialize and run GUI application

    client = Client(host, port)
    receive = client.start()

    window = tk.Tk()
    window.title('Chatroom')

    fromMessages = tk.Frame(master=window)
    scrollbar = tk.Scrollbar(master=fromMessages)
    messages = tk.Listbox(master=fromMessages, yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    client.messages = messages
    receive.messages = messages

    fromMessages.grid(row=0, column=0, columnspan=2, sticky='nsew')
    fromEntry = tk.Frame(master=window)
    textInput = tk.Entry(master=fromEntry)

    textInput.pack(fill=tk.BOTH, expand=True)
    textInput.bind('<Return>', lambda x: client.send(textInput))
    textInput.insert(0, 'Tapez votre message ici et appuyez sur Entrée pour envoyer')

    def clear_text_input(event):
        textInput.delete(0, tk.END)

    textInput.bind('<FocusIn>', clear_text_input)

    btnSend = tk.Button(
        master=window,
        text='Envoyer',
        command=lambda: client.send(textInput)
    )

    fromEntry.grid(row=1, column=0, padx=10, sticky='ew')
    btnSend.grid(row=1, column=1, pady=10, sticky='ew')

    window.rowconfigure(0, minsize=500 ,weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.mainloop()

if __name__ == '__main__':
    create_database()
    parser = argparse.ArgumentParser(description="Chat Server")
    parser.add_argument("host", help="localhost")
    parser.add_argument("-p", metavar="PORT", type=int, help="TCP port(default 1060)", default=1060)
    args = parser.parse_args()
    main(args.host, args.p)


