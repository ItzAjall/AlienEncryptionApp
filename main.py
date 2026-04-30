import sys
import os
import base64
import hashlib
import secrets
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QTextEdit, QPushButton,
    QComboBox, QFileDialog, QMessageBox, QFrame, QSizePolicy,
    QSpacerItem, QRadioButton, QButtonGroup, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QRunnable, QThreadPool
from PyQt6.QtGui import QFont

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class VexarScript:
    _GLYPHS = [
        'ꗃ','ꘘ','ꖙ','ꕷ','ꔠ','ꓴ','ꒀ','ꑊ','ꐻ','ꏫ','ꎻ','ꍡ','ꌷ','ꋗ','ꊡ','ꉣ',
        'ꈦ','ꇵ','ꆟ','ꅢ','ꄯ','ꃒ','ꂵ','ꁰ','ꀫ','꒻','꒺','꒴','꒱','꒭','꒩','꒡',
        'ꔕ','ꔻ','ꕅ','ꕻ','ꖝ','ꖵ','ꗋ','ꗵ','꘍','꘦','Ꙍ','Ꙭ','Ꚑ','ꚶ','ꛗ','꛺',
        '꜏','ꜰ','ꝃ','ꝰ','꞉','Ꞿ','ꟷ','ꠃ','꠱','ꡍ','꡺','ꢕ','ꢽ','ꣲ','ꤌ','ꤧ',
        'ꥃ','ꥬ','ꦇ','ꦶ','꧕','ꧾ','ꨑ','꨼','ꩢ','ꪄ','ꪱ','ꫂ','ꫨ','ꬍ','ꬵ','ꭄ',
        'ꭲ','ꭿ','꯱','꯿','ힼ','ힺ','ힸ','ힶ','ힴ','ힲ','ힰ','힮','힬','힪','힨','힦',
        '힤','힢','힠','힞','힜','힚','힘','힖','힔','힒','힐','힎','힌','힊','히','힆',
        '힄','힂','힀','ힾ','꿾','꿼','꿺','꿸','꿶','꿴','꿲','꿰','꿮','꿬','꿪','꿨',
        '꿦','꿤','꿢','꿠','꿞','꿜','꿚','꿘','꿖','꿔','꿒','꿐','꿎','꿌','꿊','꿈',
        '꿆','꿄','꿂','꿀','꾾','꾼','꾺','꾸','꾶','꾴','꾲','꾰','꾮','꾬','꾪','꾨',
        '꾦','꾤','꾢','꾠','꾞','꾜','꾚','꾘','꾖','꾔','꾒','꾐','꾎','꾌','꾊','꾈',
        '꾆','꾄','꾂','꾀','껾','껼','껺','껸','껶','껴','껲','껰','껮','껬','껪','껨',
        '껦','껤','껢','껠','껞','껜','껚','께','껖','껔','껒','껐','껎','껌','껊','껈',
        '껆','껄','껂','껀','꺾','꺼','꺺','꺸','꺶','꺴','꺲','꺰','꺮','꺬','꺪','꺨',
        '꺦','꺤','꺢','꺠','꺞','꺜','꺚','꺘','꺖','꺔','꺒','꺐','꺎','꺌','꺊','꺈',
        '꺆','꺄','꺂','꺀','꽾','꽼','꽺','꽸','꽶','꽴','꽲','꽰','꽮','꽬','꽪','꽨',
    ]
    _SEPARATORS = ['꧁','꧂','꧃','꧄','꧅','꧆','꧇','꧈']
    _REVERSE = {g:i for i,g in enumerate(_GLYPHS)}
    _SEP_SET = set(_SEPARATORS)
    
    @staticmethod
    def _pshift(b,i): return (b+((i*7+13)%37))&0xFF
    @staticmethod
    def _punshift(b,i): return (b-((i*7+13)%37)+256)&0xFF
    
    @classmethod
    def encode(cls, hex_str):
        hex_str = hex_str.replace(" ","").replace("\n","")
        out, si = "", 0
        for i in range(0, len(hex_str), 2):
            if i+1 >= len(hex_str): break
            b = int(hex_str[i:i+2], 16)
            out += cls._GLYPHS[cls._pshift(b, i>>1)]
            if ((i>>1)+1)%8 == 0:
                out += cls._SEPARATORS[si%len(cls._SEPARATORS)]
                si += 1
        return out
    
    @classmethod
    def decode(cls, vex):
        hex_out, idx = "", 0
        for ch in vex:
            if ch in cls._SEP_SET: continue
            if ch not in cls._REVERSE: continue
            orig = cls._punshift(cls._REVERSE[ch], idx)
            hex_out += f"{orig:02x}"
            idx += 1
        return hex_out if hex_out else None


class AESCrypto:
    KEY_LEN, NONCE_LEN = 32, 12
    SALT_LEN = 16
    
    @staticmethod
    def generate_key():
        return secrets.token_bytes(32)
    
    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        if salt is None:
            salt = secrets.token_bytes(AESCrypto.SALT_LEN)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=600000, backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt
    
    @classmethod
    def encrypt_text(cls, text: str, key: bytes, use_alien: bool = True) -> str:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(cls.NONCE_LEN)
        ct = aesgcm.encrypt(nonce, text.encode(), None)
        combined = nonce + ct
        b64 = base64.b64encode(combined).decode()
        if use_alien:
            hex_str = b64.encode().hex()
            return VexarScript.encode(hex_str)
        return b64
    
    @classmethod
    def decrypt_text(cls, text: str, key: bytes, use_alien: bool = True) -> Optional[str]:
        if use_alien:
            hex_str = VexarScript.decode(text)
            if not hex_str: return None
            try:
                b64 = bytes.fromhex(hex_str).decode()
            except:
                return None
        else:
            b64 = text
        try:
            combined = base64.b64decode(b64)
            nonce, ct = combined[:cls.NONCE_LEN], combined[cls.NONCE_LEN:]
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, None).decode()
        except:
            return None
    
    @classmethod
    def encrypt_file(cls, filepath: str, key: bytes) -> bytes:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(cls.NONCE_LEN)
        with open(filepath, 'rb') as f:
            data = f.read()
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct
    
    @classmethod
    def decrypt_file(cls, encrypted_data: bytes, key: bytes) -> bytes:
        nonce = encrypted_data[:cls.NONCE_LEN]
        ct = encrypted_data[cls.NONCE_LEN:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)


class RSACrypto:
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        private_key = rsa.generate_private_key(65537, key_size, default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem, private_key, public_key
    
    @staticmethod
    def generate_ec_keypair(curve='secp256r1'):
        curves = {'secp256r1': ec.SECP256R1(), 'secp384r1': ec.SECP384R1(), 'secp521r1': ec.SECP521R1()}
        selected_curve = curves.get(curve, ec.SECP256R1())
        private_key = ec.generate_private_key(selected_curve, default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem, private_key, public_key
    
    @staticmethod
    def generate_ed25519_keypair():
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem, private_key, public_key
    
    @staticmethod
    def load_private_key(pem_data):
        private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_key, public_key, public_pem
    
    @staticmethod
    def encrypt_text(text, public_key, use_alien: bool = True):
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        aes_key = secrets.token_bytes(32)
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, text.encode(), None)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        combined = encrypted_key + nonce + ct
        b64 = base64.b64encode(combined).decode()
        if use_alien:
            hex_str = b64.encode().hex()
            return VexarScript.encode(hex_str)
        return b64
    
    @staticmethod
    def decrypt_text(text, private_key, use_alien: bool = True):
        if use_alien:
            hex_str = VexarScript.decode(text)
            if not hex_str: return None
            try:
                b64 = bytes.fromhex(hex_str).decode()
            except:
                return None
        else:
            b64 = text
        try:
            if isinstance(private_key, bytes):
                private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
            combined = base64.b64decode(b64)
            key_size = private_key.key_size
            encrypted_key_len = key_size // 8
            encrypted_key = combined[:encrypted_key_len]
            nonce = combined[encrypted_key_len:encrypted_key_len+12]
            ct = combined[encrypted_key_len+12:]
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            aesgcm = AESGCM(aes_key)
            return aesgcm.decrypt(nonce, ct, None).decode()
        except:
            return None
    
    @staticmethod
    def encrypt_file(filepath, public_key):
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        with open(filepath, 'rb') as f:
            data = f.read()
        aes_key = secrets.token_bytes(32)
        aesgcm = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, data, None)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return encrypted_key + nonce + ct
    
    @staticmethod
    def decrypt_file(encrypted_data, private_key):
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        key_size = private_key.key_size
        encrypted_key_len = key_size // 8
        encrypted_key = encrypted_data[:encrypted_key_len]
        nonce = encrypted_data[encrypted_key_len:encrypted_key_len+12]
        ct = encrypted_data[encrypted_key_len+12:]
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, ct, None)


class WorkerSignals(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

class CryptoWorker(QRunnable):
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
    
    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            self.signals.finished.emit(result)
        except Exception as e:
            self.signals.error.emit(str(e))


class AlienEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Alien Encryption")
        self.setMinimumSize(950, 720)
        self.resize(1000, 750)
        
        self.aes_key = None
        self.aes_salt = None
        self.rsa_private = None
        self.rsa_public = None
        self.rsa_private_pem = None
        self.rsa_public_pem = None
        self.current_rsa_type = 'rsa'
        self.alien_script_enabled = True
        
        self.thread_pool = QThreadPool()
        self.thread_pool.setMaxThreadCount(4)
        
        self.aes_password_visible = False
        
        self.setup_ui()
        self.apply_theme()
        self.center()
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(12)
        
        header = QFrame()
        header.setObjectName("header")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 16, 20, 16)
        
        title_row = QHBoxLayout()
        title = QLabel("🛸 Alien Encryption")
        title.setObjectName("title")
        title_row.addWidget(title)
        title_row.addStretch()
        
        self.alien_toggle_btn = QPushButton("👽 Alien: ON")
        self.alien_toggle_btn.setObjectName("primaryBtn")
        self.alien_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.alien_toggle_btn.clicked.connect(self.toggle_alien_script)
        self.alien_toggle_btn.setFixedWidth(130)
        title_row.addWidget(self.alien_toggle_btn)
        
        header_layout.addLayout(title_row)
        
        subtitle = QLabel("AES-256-GCM | RSA | EC | Ed25519")
        subtitle.setObjectName("subtitle")
        header_layout.addWidget(subtitle)
        main_layout.addWidget(header)
        
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        main_layout.addWidget(self.tabs)
        
        self.aes_tab = self.create_aes_tab()
        self.rsa_tab = self.create_rsa_tab()
        
        self.tabs.addTab(self.aes_tab, "  🔐 AES-256  ")
        self.tabs.addTab(self.rsa_tab, "  🔑 Asymmetric  ")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("progressBar")
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximum(100)
        main_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("status")
        main_layout.addWidget(self.status_label)
    
    def toggle_alien_script(self):
        self.alien_script_enabled = not self.alien_script_enabled
        if self.alien_script_enabled:
            self.alien_toggle_btn.setText("👽 Alien: ON")
            self.alien_toggle_btn.setStyleSheet("")
            self.alien_toggle_btn.setObjectName("primaryBtn")
            self.set_status("👽 Alien script enabled", "#00d4aa")
        else:
            self.alien_toggle_btn.setText("👽 Alien: OFF")
            self.alien_toggle_btn.setObjectName("alienOffBtn")
            self.set_status("👽 Alien script disabled - output will be plain Base64", "#888")
        self.apply_theme()
    
    def create_card(self):
        card = QFrame()
        card.setObjectName("card")
        card.setFrameStyle(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        return card, layout
    
    def create_button(self, text, callback, primary=False, small=False):
        btn = QPushButton(text)
        if callback:
            btn.clicked.connect(callback)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            btn.setObjectName("primaryBtn")
        elif small:
            btn.setObjectName("smallBtn")
        else:
            btn.setObjectName("secondaryBtn")
        return btn
    
    def create_aes_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)
        
        key_card, key_layout = self.create_card()
        key_label = QLabel("🔑 Encryption Key")
        key_label.setObjectName("cardTitle")
        key_layout.addWidget(key_label)
        
        key_input_layout = QHBoxLayout()
        key_input_layout.setSpacing(8)
        
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setPlaceholderText("Enter password or hex key...")
        self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_input_layout.addWidget(self.aes_key_input)
        
        self.aes_eye_btn = QPushButton("👁")
        self.aes_eye_btn.setObjectName("iconBtn")
        self.aes_eye_btn.setToolTip("Show/Hide password")
        self.aes_eye_btn.clicked.connect(self.toggle_aes_password_visibility)
        self.aes_eye_btn.setFixedWidth(40)
        key_input_layout.addWidget(self.aes_eye_btn)
        
        paste_btn = QPushButton("📥 Paste")
        paste_btn.setObjectName("secondaryBtn")
        paste_btn.clicked.connect(self.paste_aes_key)
        key_input_layout.addWidget(paste_btn)
        
        gen_btn = self.create_button("🎲 Generate", self.gen_aes_key)
        key_input_layout.addWidget(gen_btn)
        
        copy_btn = self.create_button("📋 Copy", lambda: self.copy_to_clipboard(self.aes_key_input.text()))
        key_input_layout.addWidget(copy_btn)
        
        key_layout.addLayout(key_input_layout)
        
        self.pass_strength_label = QLabel("")
        self.pass_strength_label.setObjectName("strengthLabel")
        key_layout.addWidget(self.pass_strength_label)
        self.aes_key_input.textChanged.connect(self.check_password_strength)
        
        layout.addWidget(key_card)
        
        text_layout = QHBoxLayout()
        text_layout.setSpacing(10)
        
        input_card, input_layout = self.create_card()
        input_label = QLabel("📝 Input")
        input_label.setObjectName("cardTitle")
        input_layout.addWidget(input_label)
        
        self.aes_input = QTextEdit()
        self.aes_input.setPlaceholderText("Enter text to encrypt/decrypt...")
        input_layout.addWidget(self.aes_input)
        text_layout.addWidget(input_card)
        
        output_card, output_layout = self.create_card()
        output_header = QHBoxLayout()
        output_label = QLabel("🔮 Output")
        output_label.setObjectName("cardTitlePurple")
        output_header.addWidget(output_label)
        output_header.addStretch()
        copy_out_btn = self.create_button("📋 Copy", self.copy_aes_output, small=True)
        output_header.addWidget(copy_out_btn)
        output_layout.addLayout(output_header)
        
        self.aes_output = QTextEdit()
        self.aes_output.setPlaceholderText("Encrypted/Decrypted result...")
        self.aes_output.setReadOnly(True)
        output_layout.addWidget(self.aes_output)
        text_layout.addWidget(output_card)
        
        layout.addLayout(text_layout, 1)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        encrypt_btn = self.create_button("🔒 Encrypt", self.aes_encrypt_text, primary=True)
        decrypt_btn = self.create_button("🔓 Decrypt", self.aes_decrypt_text)
        swap_btn = self.create_button("⇄ Swap", self.swap_aes_text)
        enc_file_btn = self.create_button("📁 Encrypt File", self.aes_encrypt_file)
        dec_file_btn = self.create_button("📁 Decrypt File", self.aes_decrypt_file)
        
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(swap_btn)
        btn_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding))
        btn_layout.addWidget(enc_file_btn)
        btn_layout.addWidget(dec_file_btn)
        
        layout.addLayout(btn_layout)
        return tab
    
    def create_rsa_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)
        
        config_card, config_layout = self.create_card()
        key_type_layout = QHBoxLayout()
        key_type_layout.setSpacing(15)
        
        key_type_label = QLabel("🔧 Key Type:")
        key_type_label.setObjectName("cardTitle")
        key_type_layout.addWidget(key_type_label)
        
        self.key_type_group = QButtonGroup()
        
        self.rsa_radio = QRadioButton("RSA")
        self.rsa_radio.setChecked(True)
        self.rsa_radio.toggled.connect(self.on_key_type_changed)
        self.key_type_group.addButton(self.rsa_radio)
        key_type_layout.addWidget(self.rsa_radio)
        
        self.ec_radio = QRadioButton("EC")
        self.ec_radio.toggled.connect(self.on_key_type_changed)
        self.key_type_group.addButton(self.ec_radio)
        key_type_layout.addWidget(self.ec_radio)
        
        self.ed25519_radio = QRadioButton("Ed25519")
        self.ed25519_radio.toggled.connect(self.on_key_type_changed)
        self.key_type_group.addButton(self.ed25519_radio)
        key_type_layout.addWidget(self.ed25519_radio)
        
        key_type_layout.addStretch()
        config_layout.addLayout(key_type_layout)
        
        key_params_layout = QHBoxLayout()
        key_params_layout.setSpacing(12)
        
        self.key_param_label = QLabel("📏 Key Size:")
        self.key_param_label.setObjectName("cardTitle")
        key_params_layout.addWidget(self.key_param_label)
        
        self.key_param_combo = QComboBox()
        self.key_param_combo.addItems(["2048", "3072", "4096", "8192"])
        key_params_layout.addWidget(self.key_param_combo)
        
        gen_btn = self.create_button("🎲 Generate Keys", self.gen_rsa_keys, primary=True)
        key_params_layout.addWidget(gen_btn)
        
        import_btn = self.create_button("📥 Import Key", self.import_rsa_private)
        key_params_layout.addWidget(import_btn)
        
        save_keys_btn = self.create_button("💾 Save Keys", self.save_rsa_keys)
        key_params_layout.addWidget(save_keys_btn)
        
        key_params_layout.addStretch()
        config_layout.addLayout(key_params_layout)
        layout.addWidget(config_card)
        
        keys_card, keys_layout = self.create_card()
        
        pub_label = QLabel("🔓 Public Key")
        pub_label.setObjectName("cardTitleGreen")
        keys_layout.addWidget(pub_label)
        
        pub_row = QHBoxLayout()
        self.rsa_public_display = QLineEdit()
        self.rsa_public_display.setReadOnly(True)
        self.rsa_public_display.setPlaceholderText("Public key will appear here...")
        pub_row.addWidget(self.rsa_public_display)
        
        copy_pub_btn = QPushButton("📋")
        copy_pub_btn.setObjectName("smallBtn")
        copy_pub_btn.clicked.connect(lambda: self.copy_to_clipboard(self.rsa_public_display.text()))
        copy_pub_btn.setFixedWidth(45)
        pub_row.addWidget(copy_pub_btn)
        
        paste_pub_btn = QPushButton("📥")
        paste_pub_btn.setObjectName("smallBtn")
        paste_pub_btn.clicked.connect(lambda: self.paste_key_to_field(self.rsa_public_display))
        paste_pub_btn.setFixedWidth(45)
        pub_row.addWidget(paste_pub_btn)
        
        keys_layout.addLayout(pub_row)
        
        priv_label = QLabel("🔒 Private Key")
        priv_label.setObjectName("cardTitleRed")
        keys_layout.addWidget(priv_label)
        
        priv_row = QHBoxLayout()
        self.rsa_private_display = QLineEdit()
        self.rsa_private_display.setReadOnly(True)
        self.rsa_private_display.setPlaceholderText("Private key will appear here...")
        priv_row.addWidget(self.rsa_private_display)
        
        copy_priv_btn = QPushButton("📋")
        copy_priv_btn.setObjectName("smallBtn")
        copy_priv_btn.clicked.connect(lambda: self.copy_to_clipboard(self.rsa_private_display.text()))
        copy_priv_btn.setFixedWidth(45)
        priv_row.addWidget(copy_priv_btn)
        
        paste_priv_btn = QPushButton("📥")
        paste_priv_btn.setObjectName("smallBtn")
        paste_priv_btn.clicked.connect(lambda: self.paste_key_to_field(self.rsa_private_display))
        paste_priv_btn.setFixedWidth(45)
        priv_row.addWidget(paste_priv_btn)
        
        keys_layout.addLayout(priv_row)
        layout.addWidget(keys_card)
        
        text_layout = QHBoxLayout()
        text_layout.setSpacing(10)
        
        input_card, input_layout = self.create_card()
        input_label = QLabel("📝 Input")
        input_label.setObjectName("cardTitle")
        input_layout.addWidget(input_label)
        
        self.rsa_input = QTextEdit()
        self.rsa_input.setPlaceholderText("Enter text to encrypt/decrypt...")
        input_layout.addWidget(self.rsa_input)
        text_layout.addWidget(input_card)
        
        output_card, output_layout = self.create_card()
        output_header = QHBoxLayout()
        output_label = QLabel("🔮 Output")
        output_label.setObjectName("cardTitlePurple")
        output_header.addWidget(output_label)
        output_header.addStretch()
        copy_out_btn = self.create_button("📋 Copy", self.copy_rsa_output, small=True)
        output_header.addWidget(copy_out_btn)
        output_layout.addLayout(output_header)
        
        self.rsa_output = QTextEdit()
        self.rsa_output.setPlaceholderText("Encrypted/Decrypted result...")
        self.rsa_output.setReadOnly(True)
        output_layout.addWidget(self.rsa_output)
        text_layout.addWidget(output_card)
        
        layout.addLayout(text_layout, 1)
        
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)
        
        encrypt_btn = self.create_button("🔒 Encrypt", self.rsa_encrypt_text, primary=True)
        decrypt_btn = self.create_button("🔓 Decrypt", self.rsa_decrypt_text)
        swap_btn = self.create_button("⇄ Swap", self.swap_rsa_text)
        enc_file_btn = self.create_button("📁 Encrypt File", self.rsa_encrypt_file)
        dec_file_btn = self.create_button("📁 Decrypt File", self.rsa_decrypt_file)
        
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(swap_btn)
        btn_layout.addSpacerItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding))
        btn_layout.addWidget(enc_file_btn)
        btn_layout.addWidget(dec_file_btn)
        
        layout.addLayout(btn_layout)
        return tab
    
    def on_key_type_changed(self):
        if self.rsa_radio.isChecked():
            self.current_rsa_type = 'rsa'
            self.key_param_label.setText("📏 Key Size:")
            self.key_param_combo.clear()
            self.key_param_combo.addItems(["2048", "3072", "4096", "8192"])
        elif self.ec_radio.isChecked():
            self.current_rsa_type = 'ec'
            self.key_param_label.setText("📐 Curve:")
            self.key_param_combo.clear()
            self.key_param_combo.addItems(["secp256r1 (P-256)", "secp384r1 (P-384)", "secp521r1 (P-521)"])
        elif self.ed25519_radio.isChecked():
            self.current_rsa_type = 'ed25519'
            self.key_param_label.setText("📐 Algorithm:")
            self.key_param_combo.clear()
            self.key_param_combo.addItems(["Ed25519"])
    
    def apply_theme(self):
        alien_off_style = ""
        if not self.alien_script_enabled:
            alien_off_style = """
            #alienOffBtn {
                background-color: #252540;
                color: #888;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 12px;
            }
            #alienOffBtn:hover {
                background-color: #2d2d50;
            }
            """
        
        style = f"""
        QMainWindow {{ background-color: #0d0d1a; }}
        QWidget {{ font-family: 'Segoe UI', 'Inter', sans-serif; font-size: 13px; color: #e8e8f0; }}
        #header {{ background-color: #1a1a30; border: 1px solid #2a2a45; border-radius: 12px; }}
        #title {{ font-size: 24px; font-weight: bold; color: #00d4aa; }}
        #subtitle {{ font-size: 11px; color: #888; }}
        #mainTabs {{ background-color: transparent; }}
        #mainTabs::pane {{ border: none; background-color: transparent; }}
        #mainTabs::tab-bar {{ alignment: left; }}
        QTabBar::tab {{ background-color: #1a1a30; color: #e8e8f0; padding: 10px 20px; margin-right: 4px; border-radius: 8px 8px 0 0; font-weight: bold; font-size: 13px; }}
        QTabBar::tab:selected {{ background-color: #00d4aa; color: #0d0d1a; }}
        QTabBar::tab:hover:!selected {{ background-color: #252540; }}
        #card {{ background-color: #1a1a30; border: 1px solid #2a2a45; border-radius: 10px; }}
        #cardTitle {{ font-size: 14px; font-weight: bold; color: #e8e8f0; }}
        #cardTitlePurple {{ font-size: 14px; font-weight: bold; color: #c084fc; }}
        #cardTitleGreen {{ font-size: 14px; font-weight: bold; color: #00d4aa; }}
        #cardTitleRed {{ font-size: 14px; font-weight: bold; color: #ff6b6b; }}
        #strengthLabel {{ font-size: 11px; padding: 2px 0; }}
        QLineEdit {{ background-color: #12122a; border: 1px solid #2a2a45; border-radius: 6px; padding: 8px 12px; color: #e8e8f0; font-family: 'Consolas', monospace; font-size: 12px; }}
        QLineEdit:focus {{ border-color: #00d4aa; }}
        QTextEdit {{ background-color: #12122a; border: 1px solid #2a2a45; border-radius: 6px; padding: 10px; color: #e8e8f0; font-size: 13px; }}
        QTextEdit:focus {{ border-color: #00d4aa; }}
        QPushButton {{ background-color: #252540; color: #e8e8f0; border: none; border-radius: 6px; padding: 8px 16px; font-weight: bold; font-size: 12px; }}
        QPushButton:hover {{ background-color: #2d2d50; }}
        QPushButton:pressed {{ background-color: #1a1a30; }}
        #primaryBtn {{ background-color: #00d4aa; color: #0d0d1a; }}
        #primaryBtn:hover {{ background-color: #00e6b8; }}
        #smallBtn {{ padding: 4px 10px; font-size: 11px; min-width: 40px; max-width: 50px; }}
        #iconBtn {{ padding: 4px; font-size: 16px; background-color: #252540; min-width: 36px; max-width: 36px; }}
        #iconBtn:hover {{ background-color: #2d2d50; }}
        QRadioButton {{ color: #e8e8f0; spacing: 8px; font-size: 12px; }}
        QRadioButton::indicator {{ width: 18px; height: 18px; border-radius: 9px; border: 2px solid #2a2a45; background-color: #12122a; }}
        QRadioButton::indicator:checked {{ border-color: #00d4aa; background-color: #00d4aa; }}
        QComboBox {{ background-color: #12122a; border: 1px solid #2a2a45; border-radius: 6px; padding: 8px 12px; color: #e8e8f0; font-size: 12px; min-width: 160px; }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox::down-arrow {{ image: none; border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 6px solid #e8e8f0; margin-right: 8px; }}
        QComboBox QAbstractItemView {{ background-color: #1a1a30; border: 1px solid #2a2a45; color: #e8e8f0; selection-background-color: #00d4aa; selection-color: #0d0d1a; }}
        #progressBar {{ background-color: #12122a; border: none; border-radius: 4px; height: 6px; }}
        #progressBar::chunk {{ background-color: #00d4aa; border-radius: 4px; }}
        #status {{ font-size: 11px; color: #888; padding: 4px 0; }}
        {alien_off_style}
        """
        self.setStyleSheet(style)
    
    def check_password_strength(self, text):
        if not text:
            self.pass_strength_label.setText("")
            return
        try:
            key = bytes.fromhex(text)
            if len(key) == 32:
                self.pass_strength_label.setText("🔐 Strong hex key (256-bit)")
                self.pass_strength_label.setStyleSheet("color: #00d4aa; font-size: 11px;")
                return
        except:
            pass
        score = 0
        if len(text) >= 8: score += 1
        if len(text) >= 12: score += 1
        if len(text) >= 16: score += 1
        if any(c.isupper() for c in text): score += 1
        if any(c.islower() for c in text): score += 1
        if any(c.isdigit() for c in text): score += 1
        if any(not c.isalnum() for c in text): score += 1
        if score <= 2: strength, color = "Weak", "#ff6b6b"
        elif score <= 4: strength, color = "Medium", "#ffa500"
        else: strength, color = "Strong", "#00d4aa"
        self.pass_strength_label.setText(f"Password strength: {strength} (Will be strengthened with PBKDF2)")
        self.pass_strength_label.setStyleSheet(f"color: {color}; font-size: 11px;")
    
    def show_progress(self):
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
    
    def hide_progress(self):
        self.progress_bar.setVisible(False)
    
    def toggle_aes_password_visibility(self):
        self.aes_password_visible = not self.aes_password_visible
        if self.aes_password_visible:
            self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.aes_eye_btn.setText("🙈")
        else:
            self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.aes_eye_btn.setText("👁")
    
    def paste_aes_key(self):
        clipboard = QApplication.clipboard().text()
        if clipboard:
            self.aes_key_input.setText(clipboard.strip())
            self.set_status("📥 Key pasted from clipboard", "#2196f3")
    
    def gen_aes_key(self):
        key = AESCrypto.generate_key()
        self.aes_key_input.setText(key.hex())
        self.aes_key = key
        self.aes_salt = None
        self.set_status("✅ Strong key generated", "#00d4aa")
    
    def get_aes_key(self) -> Optional[bytes]:
        k = self.aes_key_input.text().strip()
        if not k:
            QMessageBox.warning(self, "Error", "Please enter a password or generate a key")
            return None
        try:
            key = bytes.fromhex(k)
            if len(key) == 32:
                self.aes_key = key
                self.aes_salt = None
                return key
        except:
            pass
        if self.aes_salt:
            key, _ = AESCrypto.derive_key(k, self.aes_salt)
        else:
            key, self.aes_salt = AESCrypto.derive_key(k)
        self.aes_key = key
        return key
    
    def aes_encrypt_text(self):
        text = self.aes_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "Enter text to encrypt")
            return
        key = self.get_aes_key()
        if not key:
            return
        self.run_async(AESCrypto.encrypt_text, (text, key, self.alien_script_enabled), self.show_aes_output, "🔒 Encrypting...")
    
    def aes_decrypt_text(self):
        text = self.aes_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "Paste encrypted text in Input field")
            return
        key = self.get_aes_key()
        if not key:
            return
        def on_finish(result):
            if result: self.show_aes_output(result)
            else: self.set_status("❌ Invalid key or corrupted data", "#ff6b6b")
        self.run_async(AESCrypto.decrypt_text, (text, key, self.alien_script_enabled), on_finish, "🔓 Decrypting...")
    
    def show_aes_output(self, text):
        self.aes_output.setPlainText(text)
        self.set_status("✅ Done", "#00d4aa")
        self.hide_progress()
    
    def swap_aes_text(self):
        input_text = self.aes_input.toPlainText()
        output_text = self.aes_output.toPlainText()
        self.aes_input.setPlainText(output_text)
        self.aes_output.setPlainText(input_text)
        self.set_status("⇄ Swapped", "#2196f3")
    
    def aes_encrypt_file(self):
        key = self.get_aes_key()
        if not key: return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not filepath: return
        self.show_progress()
        def task():
            encrypted = AESCrypto.encrypt_file(filepath, key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", os.path.basename(filepath) + ".enc")
            if save_path:
                with open(save_path, 'wb') as f: f.write(encrypted)
                return os.path.basename(save_path)
            return None
        def on_finish(filename):
            if filename: self.set_status(f"✅ Encrypted: {filename}", "#00d4aa")
            self.hide_progress()
        self.run_async(task, on_finish=on_finish, status_msg="📁 Encrypting file...")
    
    def aes_decrypt_file(self):
        key = self.get_aes_key()
        if not key: return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not filepath: return
        self.show_progress()
        def task():
            with open(filepath, 'rb') as f: encrypted = f.read()
            decrypted = AESCrypto.decrypt_file(encrypted, key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save decrypted file", os.path.basename(filepath).replace('.enc', ''))
            if save_path:
                with open(save_path, 'wb') as f: f.write(decrypted)
                return os.path.basename(save_path)
            return None
        def on_finish(filename):
            if filename: self.set_status(f"✅ Decrypted: {filename}", "#00d4aa")
            self.hide_progress()
        self.run_async(task, on_finish=on_finish, status_msg="📁 Decrypting file...")
    
    def copy_aes_output(self):
        text = self.aes_output.toPlainText()
        if text:
            self.copy_to_clipboard(text)
            self.set_status("📋 Copied to clipboard", "#2196f3")
    
    def gen_rsa_keys(self):
        key_param = self.key_param_combo.currentText()
        if self.current_rsa_type == 'rsa':
            key_size = int(key_param.split()[0] if ' ' in key_param else key_param)
            func, args, status = RSACrypto.generate_rsa_keypair, (key_size,), f"🎲 Generating RSA-{key_size}..."
        elif self.current_rsa_type == 'ec':
            curve_name = key_param.split()[0] if ' ' in key_param else 'secp256r1'
            func, args, status = RSACrypto.generate_ec_keypair, (curve_name,), f"🎲 Generating EC {curve_name}..."
        else:
            func, args, status = RSACrypto.generate_ed25519_keypair, (), "🎲 Generating Ed25519..."
        def on_finish(result):
            priv_pem, pub_pem, private_key, public_key = result
            self.rsa_private, self.rsa_public = private_key, public_key
            self.rsa_private_pem, self.rsa_public_pem = priv_pem, pub_pem
            self.rsa_private_display.setText(priv_pem.decode())
            self.rsa_public_display.setText(pub_pem.decode())
            self.set_status("✅ Keys generated", "#00d4aa")
        self.run_async(func, args, on_finish, status)
    
    def import_rsa_private(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Import Private Key PEM", filter="PEM files (*.pem);;All files (*.*)")
        if not filepath: return
        try:
            with open(filepath, 'rb') as f: pem_data = f.read()
            private_key, public_key, public_pem = RSACrypto.load_private_key(pem_data)
            self.rsa_private, self.rsa_public = private_key, public_key
            self.rsa_private_pem, self.rsa_public_pem = pem_data, public_pem
            self.rsa_private_display.setText(pem_data.decode())
            self.rsa_public_display.setText(public_pem.decode())
            self.set_status("✅ Private key imported", "#00d4aa")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Invalid private key: {e}")
    
    def save_rsa_keys(self):
        if not self.rsa_private_pem or not self.rsa_public_pem:
            QMessageBox.warning(self, "Error", "Generate or import keys first")
            return
        directory = QFileDialog.getExistingDirectory(self, "Select folder to save keys")
        if not directory: return
        try:
            with open(os.path.join(directory, "private_key.pem"), 'wb') as f: f.write(self.rsa_private_pem)
            with open(os.path.join(directory, "public_key.pem"), 'wb') as f: f.write(self.rsa_public_pem)
            self.set_status(f"✅ Keys saved to {directory}", "#00d4aa")
            QMessageBox.information(self, "Keys Saved", f"Keys saved successfully!\n\n⚠️ Keep your private key secure!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save keys: {e}")
    
    def paste_key_to_field(self, field):
        clipboard = QApplication.clipboard().text()
        if clipboard:
            field.setText(clipboard.strip())
            self.set_status("📥 Key pasted", "#2196f3")
    
    def get_rsa_keys(self):
        if not self.rsa_public_pem or not self.rsa_private_pem:
            QMessageBox.warning(self, "Error", "Generate or import keys first")
            return None, None
        return self.rsa_private, self.rsa_public
    
    def rsa_encrypt_text(self):
        text = self.rsa_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "Enter text to encrypt")
            return
        _, public_key = self.get_rsa_keys()
        if not public_key: return
        self.run_async(RSACrypto.encrypt_text, (text, public_key, self.alien_script_enabled), self.show_rsa_output, "🔒 Encrypting...")
    
    def rsa_decrypt_text(self):
        text = self.rsa_input.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "Paste encrypted text in Input field")
            return
        private_key, _ = self.get_rsa_keys()
        if not private_key: return
        def on_finish(result):
            if result: self.show_rsa_output(result)
            else: self.set_status("❌ Invalid key or corrupted data", "#ff6b6b")
        self.run_async(RSACrypto.decrypt_text, (text, private_key, self.alien_script_enabled), on_finish, "🔓 Decrypting...")
    
    def show_rsa_output(self, text):
        self.rsa_output.setPlainText(text)
        self.set_status("✅ Done", "#00d4aa")
        self.hide_progress()
    
    def swap_rsa_text(self):
        input_text = self.rsa_input.toPlainText()
        output_text = self.rsa_output.toPlainText()
        self.rsa_input.setPlainText(output_text)
        self.rsa_output.setPlainText(input_text)
        self.set_status("⇄ Swapped", "#2196f3")
    
    def rsa_encrypt_file(self):
        _, public_key = self.get_rsa_keys()
        if not public_key: return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not filepath: return
        self.show_progress()
        def task():
            encrypted = RSACrypto.encrypt_file(filepath, public_key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", os.path.basename(filepath) + ".enc")
            if save_path:
                with open(save_path, 'wb') as f: f.write(encrypted)
                return os.path.basename(save_path)
            return None
        def on_finish(filename):
            if filename: self.set_status(f"✅ Encrypted: {filename}", "#00d4aa")
            self.hide_progress()
        self.run_async(task, on_finish=on_finish, status_msg="📁 Encrypting file...")
    
    def rsa_decrypt_file(self):
        private_key, _ = self.get_rsa_keys()
        if not private_key: return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not filepath: return
        self.show_progress()
        def task():
            with open(filepath, 'rb') as f: encrypted = f.read()
            decrypted = RSACrypto.decrypt_file(encrypted, private_key)
            save_path, _ = QFileDialog.getSaveFileName(self, "Save decrypted file", os.path.basename(filepath).replace('.enc', ''))
            if save_path:
                with open(save_path, 'wb') as f: f.write(decrypted)
                return os.path.basename(save_path)
            return None
        def on_finish(filename):
            if filename: self.set_status(f"✅ Decrypted: {filename}", "#00d4aa")
            self.hide_progress()
        self.run_async(task, on_finish=on_finish, status_msg="📁 Decrypting file...")
    
    def copy_rsa_output(self):
        text = self.rsa_output.toPlainText()
        if text:
            self.copy_to_clipboard(text)
            self.set_status("📋 Copied to clipboard", "#2196f3")
    
    def run_async(self, func, args=None, on_finish=None, status_msg=None):
        if status_msg: self.set_status(f"⏳ {status_msg}", "#2196f3")
        worker = CryptoWorker(func, *(args or ()))
        if on_finish: worker.signals.finished.connect(on_finish)
        worker.signals.error.connect(lambda e: self.set_status(f"❌ {e}", "#ff6b6b"))
        worker.signals.error.connect(lambda: self.hide_progress())
        self.thread_pool.start(worker)
    
    def copy_to_clipboard(self, text):
        if text: QApplication.clipboard().setText(text)
    
    def set_status(self, message, color="#888"):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 11px;")
    
    def center(self):
        screen = QApplication.primaryScreen().geometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Alien Encryption")
    window = AlienEncryptionApp()
    window.show()
    sys.exit(app.exec())
