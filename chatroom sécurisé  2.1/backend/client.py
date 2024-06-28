import sys
import socket
import threading
import sqlite3
import hashlib
from PyQt5 import QtCore, QtGui, QtWidgets
import argparse
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import random
import os
import mimetypes  # Ajout de l'importation de mimetypes



def create_database():
    conn = sqlite3.connect('chat_clients.db')
    cursor = conn.cursor()

    # Create a table for clients with additional fields
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


class SendThread(QtCore.QThread):
    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        while True:
            message = input(f'{self.name}: ')
            if message.startswith('/private '):
                parts = message.split(' ', 2)
                if len(parts) < 3:
                    print("Commande incorrecte. Utilisez /private <username> <message>")
                    continue
                target_user, private_message = parts[1], parts[2]
                self.sock.sendall(f'/private {target_user} {self.name}: {private_message}'.encode('ascii'))
            elif message == 'QUIT':
                self.sock.sendall(f'Server: {self.name} a quitté(e) le chat.'.encode('ascii'))
                break
            else:
                self.sock.sendall(f'{self.name}: {message}'.encode('ascii'))

        print('\nFermeture...')
        self.sock.close()
        sys.exit()


class ReceiveThread(QtCore.QThread):
    message_received = QtCore.pyqtSignal(str, str)

    def __init__(self, sock, name):
        super().__init__()
        self.sock = sock
        self.name = name

    def run(self):
        while True:
            message = self.sock.recv(1024).decode('ascii')
            if message:
                if message.startswith('/private'):
                    parts = message.split(' ', 3)
                    if len(parts) < 4:
                        continue
                    target_user, sender, private_message = parts[1], parts[2], parts[3]
                    if target_user == self.name:
                        self.message_received.emit(f'Private from {sender}: {private_message}', 'private')
                        print(f'\rPrivate from {sender}: {private_message}\n{self.name}: ', end='')
                else:
                    self.message_received.emit(message, 'public')
                    print(f'\r{message}\n{self.name}: ', end='')
            else:
                print('\nLa connexion au serveur a été perdue\n')
                print('Fermeture...')
                self.sock.close()
                sys.exit()


class LoginDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('Login')
        self.setModal(True)
        self.resize(400, 400)  # Increase the default size to accommodate the captcha

        self.layout = QtWidgets.QVBoxLayout(self)

        self.name_label = QtWidgets.QLabel('Nom:')
        self.layout.addWidget(self.name_label)
        self.name_input = QtWidgets.QLineEdit(self)
        self.layout.addWidget(self.name_input)

        self.password_label = QtWidgets.QLabel('Mot de passe:')
        self.layout.addWidget(self.password_label)
        self.password_input = QtWidgets.QLineEdit(self)
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.captcha_label = QtWidgets.QLabel('Captcha:')
        self.layout.addWidget(self.captcha_label)

        self.captcha_image_label = QtWidgets.QLabel(self)
        self.layout.addWidget(self.captcha_image_label)

        self.captcha_input = QtWidgets.QLineEdit(self)
        self.captcha_input.setPlaceholderText('Enter the captcha text')
        self.layout.addWidget(self.captcha_input)

        self.button_layout = QtWidgets.QHBoxLayout()

        self.login_button = QtWidgets.QPushButton('Login')
        self.login_button.clicked.connect(self.accept)
        self.button_layout.addWidget(self.login_button)

        self.cancel_button = QtWidgets.QPushButton('Cancel')
        self.cancel_button.clicked.connect(self.reject)
        self.button_layout.addWidget(self.cancel_button)

        self.layout.addLayout(self.button_layout)

        self.setStyleSheet("""
            QDialog {
                background-color: #f6fff8;
            }
            QLabel {
                font-size: 14pt;
                color: black;
            }
            QLineEdit {
                background-color: white;
                padding: 10px;
                font-size: 14pt;
                border: 1px solid #000;
                border-radius: 15px;
                margin-bottom: 10px;
            }
            QPushButton {
                background-color: #2ec4b6;
                width: 100px;
                height: 40px;
                font-size: 14pt;
                border-radius: 10px;
                color: white;
            }
        """)

        self.generate_captcha()

    def get_credentials(self):
        return self.name_input.text(), self.password_input.text(), self.captcha_input.text()

    def generate_captcha(self):
        captcha_text = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
        self.captcha_text = captcha_text

        # Create an image with white background
        image = Image.new('RGB', (200, 60), 'white')
        draw = ImageDraw.Draw(image)

        try:
            font = ImageFont.truetype('arial.ttf', 36)
        except IOError:
            font = ImageFont.load_default()

        draw.text((10, 10), captcha_text, font=font, fill='black')

        # Save the image to a temporary file
        image.save('captcha.jpg')

        # Set the QPixmap from the saved image
        self.captcha_image_label.setPixmap(QtGui.QPixmap('captcha.jpg'))

    def validate_captcha(self, input_text):
        return input_text == self.captcha_text


class FileSendThread(QtCore.QThread):
    def __init__(self, sock, file_path):
        super().__init__()
        self.sock = sock
        self.file_path = file_path

    def run(self):
        try:
            with open(self.file_path, "rb") as f:
                while True:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    self.sock.sendall(chunk)
            print(f"Fichier envoyé avec succès: {self.file_path}")
        except Exception as e:
            print(f"Erreur lors de l'envoi du fichier {self.file_path}: {str(e)}")


class Client(QtWidgets.QWidget):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('Chatroom')
        self.resize(800, 600)
        self.setStyleSheet("""
            QWidget {
                background-color: #f6fff8;
            }
            QScrollArea {
                background-color: #000;
                border: 4px solid #000;
            }
            QLineEdit {
                background-color: white;
                padding: 10px;
                font-size: 14pt;
                border: 1px solid #000;
                border-radius: 15px;
            }
            QPushButton {
                background-color: #2ec4b6;
                width: 50px;
                height: 50px;
                qproperty-iconSize: 30px 30px;
                border-radius: 25px;
            }
        """)

        self.layout = QtWidgets.QVBoxLayout(self)

        self.scroll_area = QtWidgets.QScrollArea(self)
        self.scroll_area.setWidgetResizable(True)

        self.messages_widget = QtWidgets.QWidget()
        self.messages_layout = QtWidgets.QVBoxLayout(self.messages_widget)
        self.messages_layout.addStretch(1)

        self.scroll_area.setWidget(self.messages_widget)
        self.layout.addWidget(self.scroll_area)

        self.entry_layout = QtWidgets.QHBoxLayout()

        self.text_input = QtWidgets.QLineEdit(self)
        self.text_input.setPlaceholderText('Tapez votre message ici et appuyez sur Entrée pour envoyer')
        self.text_input.returnPressed.connect(self.send_message)
        self.entry_layout.addWidget(self.text_input)

        self.file_button = QtWidgets.QPushButton(self)
        self.file_button.setIcon(QtGui.QIcon('piece.webp'))  # Set the icon for the button
        self.file_button.clicked.connect(self.select_file)
        self.entry_layout.addWidget(self.file_button)

        self.send_button = QtWidgets.QPushButton(self)
        self.send_button.setIcon(QtGui.QIcon('paper_plane.png'))
        self.send_button.clicked.connect(self.send_message)
        self.entry_layout.addWidget(self.send_button)

        self.layout.addLayout(self.entry_layout)

        self.setLayout(self.layout)

    def select_file(self):
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select File to Send", "", "All Files (*)",
                                                             options=options)
        if file_path:
            self.send_file(file_path)

    def send_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
                self.sock.sendall(file_content)
                print(f"Fichier envoyé avec succès: {os.path.basename(file_path)}")
                self.display_file(file_content, os.path.basename(file_path))
        except Exception as e:
            print(f"Erreur lors de l'envoi du fichier {os.path.basename(file_path)} : {str(e)}")

    def display_file(self, file_content, filename):
        # Determine the MIME type of the file
        mime_type, _ = mimetypes.guess_type(filename)

        # Display file as a message
        file_label = QtWidgets.QLabel()
        file_label.setWordWrap(True)
        file_label.setStyleSheet("""
            QLabel {
                border: 2px solid #000;
                font-size: 12pt;
                border-radius: 15px;
                padding: 10px;
                background-color: #cbf3f0;
                color: black;
                max-width: 60%;  /* Adjust width as needed */
            }
        """)
        if mime_type and mime_type.startswith('image'):
            # If it's an image, display it as an image
            pixmap = QtGui.QPixmap()
            pixmap.loadFromData(file_content)
            file_label.setPixmap(pixmap.scaledToWidth(300))  # Adjust width as needed
        else:
            # Otherwise, display a generic file icon with the filename
            file_label.setText(f"File sent: {filename}")

        # Align file message to the right
        file_widget = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(file_widget)
        spacer = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        layout.addItem(spacer)
        layout.addWidget(file_label)
        self.messages_layout.addWidget(file_widget)
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def start(self):
        login_dialog = LoginDialog()
        if login_dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.name, self.password, captcha_input = login_dialog.get_credentials()
            if not login_dialog.validate_captcha(captcha_input):
                print('Captcha incorrect. Fermeture de la connexion...')
                sys.exit()
        else:
            sys.exit()

        print(f'Tentative de connexion au serveur {self.host}:{self.port}')
        self.sock.connect((self.host, self.port))
        print(f'Connecté au serveur {self.host}:{self.port}')

        user_exists, user_data = self.check_user_exists(self.name)

        if user_exists:
            hashed_password = user_data[2]
            if self.verify_password(self.password, hashed_password):
                print(f'Connexion réussie, bienvenue {self.name}!')
            else:
                print('Mot de passe incorrect. Fermeture de la connexion...')
                self.sock.close()
                sys.exit()
        else:
            print('Nouvel utilisateur détecté. Veuillez fournir les informations supplémentaires.')
            email, gender, dob = self.prompt_additional_info()
            if not email or not gender or not dob:
                print('Inscription annulée. Fermeture de la connexion...')
                self.sock.close()
                sys.exit()

            hashed_password = self.hash_password(self.password)
            self.register_client(self.name, hashed_password, email, gender, dob)
            print(f'Inscription réussie, bienvenue {self.name}!')

        self.send_thread = SendThread(self.sock, self.name)
        self.receive_thread = ReceiveThread(self.sock, self.name)
        self.receive_thread.message_received.connect(self.display_message)

        self.send_thread.start()
        self.receive_thread.start()

        self.sock.sendall(f'Server: {self.name} a rejoint le chat. Bienvenue!'.encode('ascii'))
        print("Tapez 'QUIT' pour quitter")


    def prompt_additional_info(self):
        email, ok = QtWidgets.QInputDialog.getText(self, 'Email', 'Adresse email:')
        if not ok:
            return None, None, None

        gender, ok = QtWidgets.QInputDialog.getText(self, 'Genre', 'Genre:')
        if not ok:
            return None, None, None

        dob, ok = QtWidgets.QInputDialog.getText(self, 'Date de naissance', 'Date de naissance (DD-MM-YYYY):')
        if not ok or not self.validate_dob(dob):
            return None, None, None

        return email, gender, dob

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
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def verify_password(self, password, hashed_password):
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

    def send_message(self):
        message = self.text_input.text()
        self.text_input.clear()
        self.display_message(f'{self.name}: {message}', 'sent')
        if message.startswith('/private '):
            parts = message.split(' ', 2)
            if len(parts) < 3:
                self.display_message("Commande incorrecte. Utilisez /private <username> <message>", 'system')
                return
            target_user, private_message = parts[1], parts[2]
            self.sock.sendall(f'/private {target_user} {self.name}: {private_message}'.encode('ascii'))
        elif message == 'QUIT':
            self.sock.sendall(f'Server: {self.name} a quitté(e) le chat.'.encode('ascii'))
            print('\nFermeture...')
            self.sock.close()
            sys.exit()
        else:
            self.sock.sendall(f'{self.name}: {message}'.encode('ascii'))

    def display_message(self, message, message_type='received'):
        name = message.split(': ')[0]
        content = ': '.join(message.split(': ')[1:])

        name_label = QtWidgets.QLabel(name)
        name_label.setStyleSheet("""
            QLabel {
                color: black;
                font-weight: bold;
                text-shadow: 1px 1px #87CEEB, -1px -1px #87CEEB, 1px -1px #87CEEB, -1px 1px #87CEEB;
            }
        """)

        message_label = QtWidgets.QLabel(content)
        message_label.setWordWrap(True)
        message_label.setStyleSheet(f"""
            QLabel {{
                border: 2px solid #000;
                font-size: 14pt;
                border-radius: 15px;
                padding: 10px;
                background-color: {"#2ec4b6" if message_type == 'sent' else "#cbf3f0"};
                color: {"white" if message_type == 'sent' else "black"};
            }}
        """)

        message_widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(message_widget)
        layout.setContentsMargins(10, 10, 10, 10)

        if message_type == 'sent':
            name_label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignTop)
            layout.addWidget(name_label)
            layout.addWidget(message_label, alignment=QtCore.Qt.AlignRight | QtCore.Qt.AlignTop)
        elif message_type == 'private':
            name_label.setText(f'Private from {name}')
            layout.addWidget(name_label, alignment=QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
            layout.addWidget(message_label, alignment=QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        else:
            layout.addWidget(name_label, alignment=QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
            layout.addWidget(message_label, alignment=QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        self.messages_layout.addWidget(message_widget)
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())


def main():
    create_database()

    parser = argparse.ArgumentParser(description='Chat Client')
    parser.add_argument('host', help='Adresse IP du serveur')
    parser.add_argument('port', type=int, help='Port du serveur')

    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    client = Client(args.host, args.port)
    client.show()
    client.start()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
