import os
import sys
import random
import hashlib
import base64
import json
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QScrollArea
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type

# Пути к изображениям (оставлены как в оригинале)
COVER_IMAGE_PATH = "cover.jpg"
APP_ICON_PATH = "app_icon.ico"


class CryptoManager:
    def __init__(self, password: str):
        self.password = password.encode('utf-8')
        self.algorithms = {
            0: {'name': 'AES-256-GCM', 'iv_len': 12, 'key_len': 32},
            1: {'name': 'ChaCha20-Poly1305', 'iv_len': 16, 'key_len': 32},
            2: {'name': 'Camellia-256-GCM', 'iv_len': 12, 'key_len': 32}
        }

    def _generate_key(self, salt: bytes, key_len: int) -> bytes:
        return hash_secret_raw(
            secret=self.password,
            salt=salt,
            time_cost=4,
            memory_cost=2 ** 20,
            parallelism=8,
            hash_len=key_len,
            type=Type.ID
        )

    def encrypt_data(self, plain_data: bytes) -> dict:
        algo_id = random.choice(list(self.algorithms.keys()))
        algo = self.algorithms[algo_id]

        salt = os.urandom(16)
        iv_nonce = os.urandom(algo['iv_len'])
        key = self._generate_key(salt, algo['key_len'])

        if algo['name'] == 'AES-256-GCM':
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv_nonce), backend=default_backend())
        elif algo['name'] == 'ChaCha20-Poly1305':
            cipher = Cipher(algorithms.ChaCha20(key, iv_nonce), mode=None, backend=default_backend())
        elif algo['name'] == 'Camellia-256-GCM':
            cipher = Cipher(algorithms.Camellia(key), modes.GCM(iv_nonce), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plain_data) + encryptor.finalize()

        return {
            'algorithm_id': algo_id,
            'salt': salt,
            'iv_nonce': iv_nonce,
            'tag': encryptor.tag if hasattr(encryptor, 'tag') else None,
            'ciphertext': ciphertext
        }

    def decrypt_data(self, encrypted_data: dict) -> bytes:
        algo = self.algorithms[encrypted_data['algorithm_id']]
        key = self._generate_key(encrypted_data['salt'], algo['key_len'])

        try:
            if algo['name'] == 'AES-256-GCM':
                cipher = Cipher(algorithms.AES(key),
                                modes.GCM(encrypted_data['iv_nonce'], encrypted_data['tag']),
                                backend=default_backend())
            elif algo['name'] == 'ChaCha20-Poly1305':
                cipher = Cipher(algorithms.ChaCha20(key, encrypted_data['iv_nonce']),
                                mode=None,
                                backend=default_backend())
            elif algo['name'] == 'Camellia-256-GCM':
                cipher = Cipher(algorithms.Camellia(key),
                                modes.GCM(encrypted_data['iv_nonce'], encrypted_data['tag']),
                                backend=default_backend())

            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("Authentication failed")


class DiffieHellman:
    def __init__(self):
        self.p, self.g = self.generate_dh_params(128)
        self.private_key = random.randrange(1, self.p)
        self.public_key = self.power(self.g, self.private_key, self.p)

    @staticmethod
    def generate_dh_params(prime_length=1024):
        p = DiffieHellman.generate_safe_prime(prime_length)
        g = DiffieHellman.find_primitive_root(p)
        return p, g

    @staticmethod
    def generate_safe_prime(length):
        while True:
            q = DiffieHellman.generate_prime(length - 1)
            p = 2 * q + 1
            if DiffieHellman.is_prime(p):
                return p

    @staticmethod
    def generate_prime(length):
        while True:
            num = random.randrange(2 ** (length - 1), 2 ** length - 1)
            if DiffieHellman.is_prime(num):
                return num

    @staticmethod
    def find_primitive_root(p):
        if p == 2:
            return 1
        p1 = 2
        p2 = (p - 1) // p1
        while True:
            g = random.randrange(2, p - 1)
            if (DiffieHellman.power(g, p1, p) != 1 and
                    DiffieHellman.power(g, p2, p) != 1):
                return g

    @staticmethod
    def is_prime(num, k=5):
        if num <= 1:
            return False
        if num <= 3:
            return True
        s = 0
        r = num - 1
        while r % 2 == 0:
            s += 1
            r //= 2

        for _ in range(k):
            a = random.randrange(2, num - 2)
            x = DiffieHellman.power(a, r, num)
            if x == 1 or x == num - 1:
                continue
            for _ in range(s - 1):
                x = DiffieHellman.power(x, 2, num)
                if x == num - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def power(base, exponent, modulus):
        result = 1
        base %= modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            base = (base * base) % modulus
            exponent //= 2
        return result

    def encrypt_password(self, password, public_key):
        k = random.randrange(1, self.p)
        a = self.power(self.g, k, self.p)
        shared_secret = self.power(public_key, k, self.p)

        key = hashlib.sha256(str(shared_secret).encode()).digest()
        password_bytes = password.encode('utf-8')
        cipher_text = self.byte_xor(password_bytes, key[:len(password_bytes)])

        return a, cipher_text.hex()

    def decrypt_password(self, a, cipher_text, private_key):
        shared_secret = self.power(a, private_key, self.p)
        key = hashlib.sha256(str(shared_secret).encode()).digest()
        cipher_text_bytes = bytes.fromhex(cipher_text)

        key_part = key[:len(cipher_text_bytes)]
        password_bytes = self.byte_xor(cipher_text_bytes, key_part)

        try:
            return password_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return password_bytes.decode('latin-1')

    @staticmethod
    def byte_xor(byte_str, key):
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(byte_str)])

    def generate_keypair(self):
        private_key = random.randrange(1, self.p)
        public_key = self.power(self.g, private_key, self.p)
        return public_key, private_key


class VigenereCipher:
    def __init__(self):
        self.alphabet = 'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ'
        self.letter_to_num = {letter: idx for idx, letter in enumerate(self.alphabet)}
        self.num_to_letter = {idx: letter for idx, letter in enumerate(self.alphabet)}

    def cipher(self, text, key, mode='encrypt'):
        text = text.upper()
        key = key.upper()
        clean_key = [c for c in key if c in self.letter_to_num]

        if not clean_key:
            raise ValueError("Ключ должен содержать хотя бы одну русскую букву")

        key_repeated = (clean_key * (len(text) // len(clean_key) + 1))[:len(text)]
        result = []
        key_index = 0

        for char in text:
            if char in self.letter_to_num:
                text_num = self.letter_to_num[char]
                key_num = self.letter_to_num[key_repeated[key_index]]

                if mode == 'encrypt':
                    new_num = (text_num + key_num) % 33
                elif mode == 'decrypt':
                    new_num = (text_num - key_num) % 33
                else:
                    raise ValueError("Неверный режим. Используйте 'encrypt' или 'decrypt'")

                result.append(self.num_to_letter[new_num])
                key_index += 1
            else:
                result.append(char)

        return ''.join(result)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.crypto_manager = None
        self.dh = DiffieHellman()
        self.vigenere = VigenereCipher()
        self.file_path = None
        self.file_path_decrypt = None

        self.setup_ui()
        self.connect_signals()

    def setup_ui(self):
        # Определение базового пути
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        # Поиск путей к изображениям
        cover_path = self.find_resource(COVER_IMAGE_PATH, "images", "cover.jpg")
        icon_path = self.find_resource(APP_ICON_PATH, "icons", "app_icon.ico")

        # Настройка главного окна
        screen = QtWidgets.QApplication.primaryScreen().availableGeometry()
        window_width = int(screen.width() * 2 / 3)
        window_height = int(screen.height() * 3 / 4)

        self.setObjectName("MainWindow")
        self.resize(window_width, window_height)
        self.setFixedSize(window_width, window_height)
        self.setWindowTitle("Workshop of secrets")
        self.setStyleSheet("QMainWindow { background-color: #f5f5f5; }")

        # Установка иконки
        if os.path.exists(icon_path):
            try:
                self.setWindowIcon(QtGui.QIcon(icon_path))
            except Exception as e:
                print(f"Ошибка загрузки иконки: {str(e)}")
        else:
            print(f"Файл иконки не найден: {icon_path}")

        # Центральный виджет
        self.centralwidget = QtWidgets.QWidget(self)
        self.setCentralWidget(self.centralwidget)
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setContentsMargins(10, 10, 10, 10)

        # Настройка вкладок
        self.tabWidget = QtWidgets.QTabWidget()
        self.tabWidget.setStyleSheet(self.get_tab_style())
        self.verticalLayout.addWidget(self.tabWidget)

        # Создание вкладок
        self.create_cover_tab(cover_path, window_width, window_height)
        self.create_instruction_tab(window_width, window_height)
        self.create_encrypt_tab(window_width, window_height)
        self.create_decrypt_tab(window_width, window_height)

    def find_resource(self, original_path, subfolder, default_name):
        if os.path.exists(original_path):
            return original_path

        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        possible_paths = [
            os.path.join(base_dir, subfolder, default_name),
            os.path.join(base_dir, default_name),
            os.path.join(os.getcwd(), default_name)
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        return original_path

    def get_tab_style(self):
        return """
            QTabWidget::pane { border: 1px solid #cccccc; border-radius: 5px; padding: 5px; background: white; }
            QTabBar::tab { padding: 8px; min-width: 100px; background: #e0e0e0; border: 1px solid #cccccc; 
                            border-radius: 5px; margin-right: 2px; }
            QTabBar::tab:selected { background: #4CAF50; color: white; }
            QScrollArea { border: none; }
        """

    def create_cover_tab(self, cover_path, window_width, window_height):
        tab = QtWidgets.QWidget()
        tab.setStyleSheet("background: white;")

        cover_label = QtWidgets.QLabel(tab)
        cover_label.setGeometry(20, 20, window_width - 60, window_height - 100)
        cover_label.setAlignment(QtCore.Qt.AlignCenter)
        cover_label.setStyleSheet("QLabel { border: 2px dashed #aaaaaa; border-radius: 10px; }")

        if os.path.exists(cover_path):
            try:
                pixmap = QtGui.QPixmap(cover_path)
                pixmap = pixmap.scaled(
                    cover_label.width() - 20,
                    cover_label.height() - 20,
                    QtCore.Qt.KeepAspectRatio,
                    QtCore.Qt.SmoothTransformation
                )
                cover_label.setPixmap(pixmap)
            except Exception as e:
                cover_label.setText("Ошибка загрузки изображения")
                print(f"Ошибка загрузки обложки: {str(e)}")
        else:
            cover_label.setText("Обложка не найдена")
            cover_label.setStyleSheet(
                "QLabel { font-size: 24px; color: #555555; border: 2px dashed #aaaaaa; border-radius: 10px; }")
            print(f"Файл обложки не найден: {cover_path}")

        self.tabWidget.addTab(tab, "Обложка")

    def create_instruction_tab(self, window_width, window_height):
        tab = QtWidgets.QWidget()
        tab.setStyleSheet("background: white;")

        text_edit = QtWidgets.QTextEdit(tab)
        text_edit.setGeometry(20, 20, window_width - 60, window_height - 100)
        text_edit.setHtml(self.get_instruction_html())
        text_edit.setReadOnly(True)

        self.tabWidget.addTab(tab, "Инструкция")

    def get_instruction_html(self):
        return """
            <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN" "http://www.w3.org/TR/REC-html40/strict.dtd">
            <html><head><meta name="qrichtext" content="1" /><style type="text/css">
            p, li { white-space: pre-wrap; }
            </style></head><body style=" font-family:'Segoe UI'; font-size:11pt; font-weight:400; font-style:normal;">
            <h1 style="text-align: center; color: #4CAF50;">Инструкция по использованию</h1>

            <h2>1. Общее описание</h2>
            <p>Программа "Workshop of secrets" позволяет шифровать и дешифровать текст, пароли и файлы с использованием современных криптографических алгоритмов. Основные возможности:</p>
            <ul>
                <li>Шифрование/дешифрование текста с помощью шифра Виженера</li>
                <li>Шифрование/дешифрование файлов с использованием AES-256-GCM, ChaCha20-Poly1305 и Camellia-256-GCM</li>
                <li>Шифрование/дешифрование паролей с использованием алгоритма Диффи-Хеллмана</li>
                <li>Сохранение результатов в текстовых файлах и бинарных форматах</li>
            </ul>

            <h2>2. Шифрование данных</h2>
            <h3>2.1. Шифрование текста</h3>
            <ol>
                <li>Перейдите на вкладку "Шифровка"</li>
                <li>Введите текст в поле "Введите текст для шифрования"</li>
                <li>Введите пароль в поле "Введите пароль"</li>
                <li>Нажмите "Зашифровать текст"</li>
                <li>Результат будет сохранен в файл encrypted_text.txt</li>
            </ol>

            <h3>2.2. Шифрование файлов</h3>
            <ol>
                <li>На вкладке "Шифровка" нажмите "Выбрать файл"</li>
                <li>Выберите файл для шифрования</li>
                <li>Введите пароль</li>
                <li>Нажмите "Зашифровать файл"</li>
                <li>Сохраните результат как файл с расширением .bin</li>
            </ol>

            <h3>2.3. Шифрование пароля</h3>
            <ol>
                <li>На вкладке "Шифровка" введите пароль</li>
                <li>Нажмите "Зашифровать пароль"</li>
                <li>Результат будет сохранен в файл encrypted_password.txt</li>
            </ol>

            <h2>3. Дешифрование данных</h2>
            <h3>3.1. Дешифрование текста</h3>
            <ol>
                <li>Перейдите на вкладку "Дешифровка"</li>
                <li>Введите зашифрованный текст в первое поле</li>
                <li>Введите параметр 'a' из файла результатов</li>
                <li>Введите зашифрованный пароль из файла результатов</li>
                <li>Введите приватный ключ из файла результатов</li>
                <li>Нажмите "Дешифровать текст"</li>
            </ol>

            <h3>3.2. Дешифрование файлов</h3>
            <ol>
                <li>На вкладке "Дешифровка" нажмите "Выбрать файл"</li>
                <li>Выберите зашифрованный файл с расширением .bin</li>
                <li>Введите пароль, использованный при шифровании</li>
                <li>Нажмите "Дешифровать файл"</li>
                <li>Сохраните результат как файл с оригинальным расширением</li>
            </ol>

            <h3>3.3. Дешифрование пароля</h3>
            <ol>
                <li>Перейдите на вкладку "Дешифровка"</li>
                <li>Введите параметр 'a' из файла результатов</li>
                <li>Введите зашифрованный пароль из файла результатов</li>
                <li>Введите приватный ключ из файла результатов</li>
                <li>Нажмите "Дешифровать пароль"</li>
                <li>Результат (расшифрованный пароль) будет сохранен в файл decrypted_password.txt</li>
            </ol>
            <p style="color: #F44336;"><b>Важно:</b> Если пароль содержит специальные символы, убедитесь что они правильно отображаются в файле результатов.</p>

            <h2>4. Важные примечания</h2>
            <ul>
                <li>Текстовые результаты сохраняются в формате TXT, а зашифрованные файлы в формате BIN</li>
                <li>Для дешифрования текста или пароля нужны все три параметра: a, зашифрованный пароль и приватный ключ</li>
                <li>Не теряйте параметры дешифрования - без них восстановление данных невозможно</li>
                <li>Используйте надежные пароли длиной от 8 символов</li>
                <li>Файлы шифруются с использованием стойких криптографических алгоритмов</li>
            </ul>

            <h2 style="color: #F44336;">Внимание!</h2>
            <p>Программа не сохраняет ваши пароли и ключи. Все криптографические параметры генерируются локально на вашем компьютере и никуда не передаются. Сохраняйте все сгенерированные файлы с результатами шифрования в надежном месте.</p>
            </body></html>
        """

    def create_encrypt_tab(self, window_width, window_height):
        tab = QtWidgets.QWidget()
        tab.setStyleSheet("background: #e6f2ff;")

        scroll_area = QScrollArea(tab)
        scroll_area.setGeometry(0, 0, window_width, window_height - 50)
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet(self.get_scroll_style())

        scroll_content = QtWidgets.QWidget()
        scroll_area.setWidget(scroll_content)
        scroll_content.setMinimumSize(window_width - 20, int(window_height * 1.5))

        # Параметры элементов
        input_width = window_width - 100
        input_height = 80
        button_width = 180
        button_height = 50
        vertical_spacing = 30

        # Создание элементов
        self.textInput = self.create_input(scroll_content, 50, "Введите текст для шифрования (необязательно)",
                                           input_width, input_height)
        self.passwordInput = self.create_input(scroll_content, 50 + input_height + vertical_spacing,
                                               "Введите пароль (необязательно)", input_width, input_height,
                                               password=True)

        self.uploadButton = self.create_button(scroll_content,
                                               (window_width - button_width * 2 - 20) // 2,
                                               50 + (input_height + vertical_spacing) * 2,
                                               "Выбрать файл", "#2196F3", button_width, button_height,
                                               icon=QtWidgets.QStyle.SP_DirOpenIcon)

        self.fileLabel = QtWidgets.QLabel(scroll_content)
        self.fileLabel.setGeometry(
            (window_width - button_width * 2 - 20) // 2 + button_width + 20,
            50 + (input_height + vertical_spacing) * 2,
            button_width,
            button_height
        )
        self.fileLabel.setText("Файл не выбран")
        self.fileLabel.setStyleSheet(self.get_label_style())
        self.fileLabel.setAlignment(QtCore.Qt.AlignCenter)

        double_button_width = (button_width * 2 + 10) // 2
        self.encryptTextButton = self.create_button(
            scroll_content,
            (window_width - double_button_width * 2 - 10) // 2,
            50 + (input_height + vertical_spacing) * 2 + button_height + vertical_spacing,
            "Зашифровать текст", "#4CAF50", double_button_width, button_height,
            icon=QtWidgets.QStyle.SP_ComputerIcon
        )

        self.encryptFileButton = self.create_button(
            scroll_content,
            (window_width - double_button_width * 2 - 10) // 2 + double_button_width + 10,
            50 + (input_height + vertical_spacing) * 2 + button_height + vertical_spacing,
            "Зашифровать файл", "#2196F3", double_button_width, button_height,
            icon=QtWidgets.QStyle.SP_FileIcon
        )

        self.encryptPasswordButton = self.create_button(
            scroll_content,
            (window_width - button_width) // 2,
            50 + (input_height + vertical_spacing) * 3 + button_height + vertical_spacing,
            "Зашифровать пароль", "#9C27B0", button_width, button_height,
            icon=QtWidgets.QStyle.SP_ComputerIcon
        )

        self.tabWidget.addTab(tab, "Шифровка")

    def create_decrypt_tab(self, window_width, window_height):
        tab = QtWidgets.QWidget()
        tab.setStyleSheet("background: #e6f2ff;")

        scroll_area = QScrollArea(tab)
        scroll_area.setGeometry(0, 0, window_width, window_height - 50)
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet(self.get_scroll_style())

        scroll_content = QtWidgets.QWidget()
        scroll_area.setWidget(scroll_content)
        scroll_content.setMinimumSize(window_width - 20, int(window_height * 1.5))

        # Параметры элементов
        input_width = window_width - 100
        input_height = 80
        button_width = 180
        button_height = 50
        vertical_spacing = 30

        # Создание элементов
        self.textInput2 = self.create_input(scroll_content, 50, "Введите зашифрованный текст (необязательно)",
                                            input_width, input_height)
        self.passwordInput2 = self.create_input(scroll_content, 50 + input_height + vertical_spacing,
                                                "Введите пароль для дешифрования файла", input_width, input_height,
                                                password=True)

        self.aInput = self.create_input(scroll_content, 50 + (input_height + vertical_spacing) * 2,
                                        "Введите параметр 'a' (из файла результатов)", input_width, input_height)
        self.cipherInput = self.create_input(scroll_content, 50 + (input_height + vertical_spacing) * 3,
                                             "Введите зашифрованный пароль (из файла результатов)", input_width,
                                             input_height)
        self.privateKeyInput = self.create_input(scroll_content, 50 + (input_height + vertical_spacing) * 4,
                                                 "Введите приватный ключ (из файла результатов)", input_width,
                                                 input_height)

        self.uploadButton2 = self.create_button(scroll_content,
                                                (window_width - button_width * 2 - 20) // 2,
                                                50 + (input_height + vertical_spacing) * 5,
                                                "Выбрать файл", "#2196F3", button_width, button_height,
                                                icon=QtWidgets.QStyle.SP_DirOpenIcon)

        self.fileLabel2 = QtWidgets.QLabel(scroll_content)
        self.fileLabel2.setGeometry(
            (window_width - button_width * 2 - 20) // 2 + button_width + 20,
            50 + (input_height + vertical_spacing) * 5,
            button_width,
            button_height
        )
        self.fileLabel2.setText("Файл не выбран")
        self.fileLabel2.setStyleSheet(self.get_label_style())
        self.fileLabel2.setAlignment(QtCore.Qt.AlignCenter)

        double_button_width = (button_width * 2 + 10) // 2
        button_y_pos = 50 + (input_height + vertical_spacing) * 6

        self.decryptTextButton = self.create_button(
            scroll_content,
            (window_width - double_button_width * 2 - 10) // 2,
            button_y_pos,
            "Дешифровать текст", "#FF9800", double_button_width, button_height,
            icon=QtWidgets.QStyle.SP_ComputerIcon
        )

        self.decryptFileButton = self.create_button(
            scroll_content,
            (window_width - double_button_width * 2 - 10) // 2 + double_button_width + 10,
            button_y_pos,
            "Дешифровать файл", "#2196F3", double_button_width, button_height,
            icon=QtWidgets.QStyle.SP_FileIcon
        )

        self.decryptPasswordButton = self.create_button(
            scroll_content,
            (window_width - button_width) // 2,
            button_y_pos + button_height + vertical_spacing,
            "Дешифровать пароль", "#9C27B0", button_width, button_height,
            icon=QtWidgets.QStyle.SP_ComputerIcon
        )

        self.tabWidget.addTab(tab, "Дешифровка")

    def create_input(self, parent, y_pos, placeholder, width, height, password=False):
        input_field = QtWidgets.QLineEdit(parent)
        input_field.setGeometry(
            (parent.width() - width) // 2,
            y_pos,
            width,
            height
        )
        input_field.setPlaceholderText(placeholder)
        input_field.setStyleSheet("""
            QLineEdit {
                font-size: 14px;
                padding: 10px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                background: white;
            }
        """)
        if password:
            input_field.setEchoMode(QtWidgets.QLineEdit.Password)
        return input_field

    def create_button(self, parent, x, y, text, color, width, height, icon=None):
        btn = QtWidgets.QPushButton(parent)
        btn.setGeometry(x, y, width, height)
        btn.setText(text)
        btn.setStyleSheet(f"""
            QPushButton {{
                font-size: 14px;
                font-weight: bold;
                background-color: {color};
                color: white;
                border: none;
                border-radius: 5px;
                padding: 5px;
            }}
            QPushButton:hover {{
                background-color: #{hex(int(int(color[1:3], 16) * 0.9))[2:] +
                                    hex(int(int(color[3:5], 16) * 0.9))[2:] +
                                    hex(int(int(color[5:7], 16) * 0.9))[2:]};
            }}
        """)
        if icon:
            btn.setIcon(QtWidgets.QApplication.style().standardIcon(icon))
        return btn

    def get_scroll_style(self):
        return """
            QScrollArea { border: none; }
            QScrollBar:vertical { width: 12px; background-color: #f1f1f1; }
            QScrollBar::handle:vertical { background-color: #c1c1c1; border-radius: 6px; min-height: 20px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        """

    def get_label_style(self):
        return """
            QLabel {
                font-size: 14px;
                color: #555555;
                background: white;
                border: 1px solid #cccccc;
                border-radius: 5px;
                padding: 5px;
            }
        """

    def connect_signals(self):
        self.uploadButton.clicked.connect(self.upload_file)
        self.uploadButton2.clicked.connect(self.upload_file_decrypt)
        self.encryptTextButton.clicked.connect(self.encrypt_text)
        self.encryptFileButton.clicked.connect(self.encrypt_file)
        self.encryptPasswordButton.clicked.connect(self.encrypt_password_only)
        self.decryptTextButton.clicked.connect(self.decrypt_text)
        self.decryptFileButton.clicked.connect(self.decrypt_file)
        self.decryptPasswordButton.clicked.connect(self.decrypt_password_only)

    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "All Files (*)")
        if file_path:
            self.fileLabel.setText(f"Файл: {os.path.basename(file_path)[:20]}...")
            self.file_path = file_path
            QMessageBox.information(self, "Файл выбран",
                                    f"Файл {os.path.basename(file_path)} готов к шифрованию.")

    def upload_file_decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите файл", "", "All Files (*)")
        if file_path:
            self.fileLabel2.setText(f"Файл: {os.path.basename(file_path)[:20]}...")
            self.file_path_decrypt = file_path
            QMessageBox.information(self, "Файл выбран",
                                    f"Файл {os.path.basename(file_path)} готов к дешифрованию.")

    def save_to_file(self, content, default_name="result.txt"):
        file_path, _ = QFileDialog.getSaveFileName(self, "Сохранить результат", default_name,
                                                   "Text Files (*.txt);;All Files (*)")
        if file_path:
            if not file_path.endswith('.txt'):
                file_path += '.txt'

            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                QMessageBox.information(self, "Успех", f"Результат сохранен в:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Ошибка сохранения:\n{str(e)}")

    def encrypt_text(self):
        text = self.textInput.text()
        password = self.passwordInput.text()

        if not text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования")
            return
        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования")
            return

        try:
            encrypted_text = self.vigenere.cipher(text, password, 'encrypt')
            public_key, private_key = self.dh.generate_keypair()
            a, encrypted_password = self.dh.encrypt_password(password, public_key)

            result = f"Зашифрованный текст (Виженер):\n{encrypted_text}\n\n" \
                     f"Параметры для дешифрования:\n" \
                     f"a: {a}\n" \
                     f"Зашифрованный пароль: {encrypted_password}\n" \
                     f"Приватный ключ: {private_key}\n\n" \
                     f"Системные параметры:\n" \
                     f"p: {self.dh.p}\ng: {self.dh.g}"

            self.save_to_file(result, "encrypted_text.txt")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования текста:\n{str(e)}")

    def encrypt_file(self):
        password = self.passwordInput.text()

        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования файла")
            return
        if not self.file_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для шифрования")
            return

        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()

            crypto = CryptoManager(password)
            encrypted_data = crypto.encrypt_data(file_data)

            data_to_save = {
                'algorithm_id': encrypted_data['algorithm_id'],
                'salt': base64.b64encode(encrypted_data['salt']).decode('utf-8'),
                'iv_nonce': base64.b64encode(encrypted_data['iv_nonce']).decode('utf-8'),
                'tag': base64.b64encode(encrypted_data['tag']).decode('utf-8') if encrypted_data['tag'] else None,
                'ciphertext': base64.b64encode(encrypted_data['ciphertext']).decode('utf-8'),
                'original_filename': os.path.basename(self.file_path)
            }

            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить зашифрованный файл",
                os.path.splitext(os.path.basename(self.file_path))[0] + ".bin",
                "Encrypted Files (*.bin);;All Files (*)"
            )

            if file_path:
                if not file_path.endswith('.bin'):
                    file_path += '.bin'

                with open(file_path, 'w') as f:
                    json.dump(data_to_save, f)

                QMessageBox.information(self, "Успех", f"Файл зашифрован и сохранен:\n{file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования файла:\n{str(e)}")

    def encrypt_password_only(self):
        password = self.passwordInput.text()

        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для шифрования")
            return

        try:
            public_key, private_key = self.dh.generate_keypair()
            a, encrypted_password = self.dh.encrypt_password(password, public_key)

            result = f"Зашифрованные данные пароля:\n\n" \
                     f"a: {a}\n" \
                     f"Зашифрованный пароль: {encrypted_password}\n" \
                     f"Приватный ключ: {private_key}\n\n" \
                     f"Параметры системы:\n" \
                     f"p: {self.dh.p}\n" \
                     f"g: {self.dh.g}"

            self.save_to_file(result, "encrypted_password.txt")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка шифрования пароля:\n{str(e)}")

    def decrypt_text(self):
        encrypted_text = self.textInput2.text()
        a_text = self.aInput.text()
        cipher_text = self.cipherInput.text()
        private_key_text = self.privateKeyInput.text()

        if not encrypted_text:
            QMessageBox.warning(self, "Ошибка", "Введите текст для дешифрования")
            return
        if not a_text or not cipher_text or not private_key_text:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля для дешифрования")
            return

        try:
            a = int(a_text.strip())
            private_key = int(private_key_text.strip())
            decrypted_password = self.dh.decrypt_password(a, cipher_text, private_key)
            decrypted_text = self.vigenere.cipher(encrypted_text, decrypted_password, 'decrypt')

            self.save_to_file(f"Расшифрованный текст:\n{decrypted_text}\n\nПароль: {decrypted_password}",
                              "decrypted_text.txt")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка дешифрования текста:\n{str(e)}")

    def decrypt_file(self):
        password = self.passwordInput2.text()

        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль для дешифрования файла")
            return
        if not self.file_path_decrypt:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для дешифрования")
            return

        try:
            with open(self.file_path_decrypt, 'r') as f:
                encrypted_data = json.load(f)

            encrypted_data_bytes = {
                'algorithm_id': encrypted_data['algorithm_id'],
                'salt': base64.b64decode(encrypted_data['salt']),
                'iv_nonce': base64.b64decode(encrypted_data['iv_nonce']),
                'tag': base64.b64decode(encrypted_data['tag']) if encrypted_data['tag'] else None,
                'ciphertext': base64.b64decode(encrypted_data['ciphertext'])
            }

            crypto = CryptoManager(password)
            decrypted_data = crypto.decrypt_data(encrypted_data_bytes)

            original_filename = encrypted_data.get('original_filename', 'decrypted_file')
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Сохранить расшифрованный файл",
                original_filename,
                "All Files (*)"
            )

            if file_path:
                with open(file_path, 'wb') as f:
                    f.write(decrypted_data)

                QMessageBox.information(self, "Успех", f"Файл расшифрован и сохранен:\n{file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка дешифрования файла:\n{str(e)}")

    def decrypt_password_only(self):
        a_text = self.aInput.text()
        cipher_text = self.cipherInput.text()
        private_key_text = self.privateKeyInput.text()

        if not a_text or not cipher_text or not private_key_text:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля для дешифрования пароля")
            return

        try:
            a = int(a_text.strip())
            private_key = int(private_key_text.strip())
            decrypted_password = self.dh.decrypt_password(a, cipher_text, private_key)

            self.save_to_file(f"Расшифрованный пароль:\n{decrypted_password}", "decrypted_password.txt")

        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка дешифрования пароля:\n{str(e)}")


def setup_qt_plugins():
    plugin_path_found = None

    # Стандартный путь при установке через pip
    try:
        import PyQt5
        base_dir = os.path.dirname(PyQt5.__file__)
        plugin_path = os.path.join(base_dir, "Qt5", "plugins")
        if os.path.exists(plugin_path):
            plugin_path_found = plugin_path
    except ImportError:
        pass

    # Альтернативный путь
    if not plugin_path_found:
        try:
            import PyQt5
            base_dir = os.path.dirname(PyQt5.__file__)
            plugin_path = os.path.join(base_dir, "Qt", "plugins")
            if os.path.exists(plugin_path):
                plugin_path_found = plugin_path
        except ImportError:
            pass

    # Относительный путь для упакованных приложений
    if not plugin_path_found:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        plugin_path = os.path.join(script_dir, "PyQt5", "Qt5", "plugins")
        if os.path.exists(plugin_path):
            plugin_path_found = plugin_path

    # Использование переменной окружения
    if not plugin_path_found and 'QT_QPA_PLATFORM_PLUGIN_PATH' in os.environ:
        if os.path.exists(os.environ['QT_QPA_PLATFORM_PLUGIN_PATH']):
            plugin_path_found = os.environ['QT_QPA_PLATFORM_PLUGIN_PATH']

    # Установка пути
    if plugin_path_found:
        os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = plugin_path_found
    else:
        # Последняя попытка
        python_base = sys.prefix
        plugin_path = os.path.join(python_base, "Lib", "site-packages", "PyQt5", "Qt5", "plugins")
        if os.path.exists(plugin_path):
            os.environ['QT_QPA_PLATFORM_PLUGIN_PATH'] = plugin_path
        else:
            print("Предупреждение: Не удалось найти плагины Qt")


if __name__ == "__main__":
    setup_qt_plugins()

    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
