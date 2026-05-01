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
    QSpacerItem, QRadioButton, QButtonGroup, QProgressBar, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QFont, QIcon, QScreen

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


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
    NONCE_LEN = 12
    CHUNK_SIZE = 64 * 1024 * 1024  # 64MB chunks for large files
    MAX_GCM_SIZE = 2**31 - 1  # ~2GB limit for single GCM operation
    
    @staticmethod
    def generate_key(): return secrets.token_bytes(32)
    
    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> tuple:
        if salt is None: salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000, backend=default_backend())
        return kdf.derive(password.encode()), salt
    
    @classmethod
    def encrypt_text(cls, text: str, key: bytes, use_alien: bool = True, one_time: bool = False) -> str:
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        associated_data = b"one_time" if one_time else b""
        ct = aesgcm.encrypt(nonce, text.encode(), associated_data)
        result = nonce + ct
        if one_time:
            result = b"\x01" + result  # Prefix to indicate one-time
        else:
            result = b"\x00" + result  # Prefix to indicate reusable
        b64 = base64.b64encode(result).decode()
        return VexarScript.encode(b64.encode().hex()) if use_alien else b64
    
    @classmethod
    def decrypt_text(cls, text: str, key: bytes, use_alien: bool = True) -> Optional[str]:
        try:
            if use_alien:
                h = VexarScript.decode(text)
                if not h: return None
                b64 = bytes.fromhex(h).decode()
            else:
                b64 = text
            data = base64.b64decode(b64)
            one_time = data[0] == 1
            aesgcm = AESGCM(key)
            associated_data = b"one_time" if one_time else b""
            return aesgcm.decrypt(data[1:13], data[13:], associated_data).decode()
        except: return None
    
    @classmethod
    def encrypt_file(cls, filepath: str, key: bytes, progress_callback=None) -> bytes:
        """Chunked AES-GCM encryption for files of any size"""
        file_size = os.path.getsize(filepath)
        
        # Generate master key components using HKDF
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'file-encryption', backend=default_backend())
        key_material = hkdf.derive(key)
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        
        result = bytearray()
        result.extend(b"AESGCM_CHUNKED")  # 16 byte header
        result.extend(secrets.token_bytes(16))  # Random file ID
        
        chunk_index = 0
        processed = 0
        
        # Calculate number of chunks
        total_chunks = (file_size + cls.CHUNK_SIZE - 1) // cls.CHUNK_SIZE
        
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(cls.CHUNK_SIZE)
                if not chunk: break
                
                # Derive unique key for this chunk
                chunk_info = chunk_index.to_bytes(8, 'big')
                chunk_kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=mac_key, info=chunk_info, backend=default_backend())
                chunk_key = chunk_kdf.derive(enc_key)
                
                # Generate unique nonce
                nonce = hashlib.sha256(chunk_info + key).digest()[:12]
                
                # Encrypt chunk with GCM
                aesgcm = AESGCM(chunk_key)
                ct = aesgcm.encrypt(nonce, chunk, chunk_info)
                
                # Store: chunk_index (8) + nonce (12) + ciphertext
                result.extend(chunk_index.to_bytes(8, 'big'))
                result.extend(nonce)
                result.extend(ct)
                
                chunk_index += 1
                processed += len(chunk)
                if progress_callback:
                    progress_callback(int(processed * 100 / file_size))
        
        # HMAC over entire result
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(bytes(result))
        result.extend(h.finalize())
        
        return bytes(result)
    
    @classmethod
    def decrypt_file(cls, data: bytes, key: bytes, progress_callback=None) -> bytes:
        """Chunked AES-GCM decryption"""
        # Verify and extract
        mac_tag = data[-32:]
        payload = data[:-32]
        
        # Derive keys
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'file-encryption', backend=default_backend())
        key_material = hkdf.derive(key)
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        
        # Verify integrity
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(payload)
        try:
            h.verify(mac_tag)
        except:
            raise ValueError("File integrity check failed - data may be corrupted or tampered")
        
        # Skip header
        header = payload[:32]  # "AESGCM_CHUNKED" + file_id
        chunk_data = payload[32:]
        
        result = bytearray()
        offset = 0
        total_size = len(chunk_data)
        
        while offset < total_size:
            chunk_index = int.from_bytes(chunk_data[offset:offset+8], 'big')
            offset += 8
            
            nonce = chunk_data[offset:offset+12]
            offset += 12
            
            # Determine remaining data size
            remaining = total_size - offset
            
            # Derive chunk key
            chunk_info = chunk_index.to_bytes(8, 'big')
            chunk_kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=mac_key, info=chunk_info, backend=default_backend())
            chunk_key = chunk_kdf.derive(enc_key)
            
            # Decrypt chunk
            aesgcm = AESGCM(chunk_key)
            try:
                ct = chunk_data[offset:total_size]
                plaintext = aesgcm.decrypt(nonce, ct, chunk_info)
                result.extend(plaintext)
                break  # Last chunk
            except:
                offset += 12
                aesgcm = AESGCM(chunk_key)
                ct = chunk_data[offset:offset+65536+16]  # Approximate chunk
                plaintext = aesgcm.decrypt(nonce, ct, chunk_info)
                result.extend(plaintext)
                offset += len(ct)
                break
        
        return bytes(result)


class RSACrypto:
    @staticmethod
    def generate_rsa(key_size=2048):
        sk = rsa.generate_private_key(65537, key_size, default_backend())
        pk = sk.public_key()
        return (sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
                pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), sk, pk)
    
    @staticmethod
    def generate_ec(curve='secp256r1'):
        curves = {'secp256r1': ec.SECP256R1(), 'secp384r1': ec.SECP384R1(), 'secp521r1': ec.SECP521R1()}
        sk = ec.generate_private_key(curves.get(curve, ec.SECP256R1()), default_backend())
        pk = sk.public_key()
        return (sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
                pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), sk, pk)
    
    @staticmethod
    def generate_ed25519():
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        return (sk.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()),
                pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), sk, pk)
    
    @staticmethod
    def load_private(pem_data):
        sk = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
        pk = sk.public_key()
        return sk, pk, pk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    @staticmethod
    def _ed_to_x25519_pub(ed_pk):
        raw = ed_pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return X25519PublicKey.from_public_bytes(raw)
    
    @staticmethod
    def _ed_to_x25519_priv(ed_sk):
        raw = ed_sk.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        return X25519PrivateKey.from_private_bytes(raw)
    
    @classmethod
    def encrypt_text(cls, text, public_key, use_alien: bool = True, one_time: bool = False):
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        aes_key = secrets.token_bytes(32)
        ct = AESCrypto.encrypt_text(text, aes_key, use_alien=False, one_time=one_time).encode()
        if hasattr(public_key, 'curve'):
            eph_sk = ec.generate_private_key(public_key.curve, default_backend())
            shared = eph_sk.exchange(ec.ECDH(), public_key)
            derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'enc', backend=default_backend()).derive(shared)
            enc_key = bytes(a ^ b for a, b in zip(aes_key, derived))
            eph_pk = eph_sk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            combined = len(eph_pk).to_bytes(4, 'big') + eph_pk + enc_key + ct
        elif hasattr(public_key, 'encrypt'):
            enc_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            combined = len(enc_key).to_bytes(4, 'big') + enc_key + ct
        else:
            eph_sk = X25519PrivateKey.generate()
            x25519_pk = cls._ed_to_x25519_pub(public_key)
            shared = eph_sk.exchange(x25519_pk)
            derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'enc', backend=default_backend()).derive(shared)
            enc_key = bytes(a ^ b for a, b in zip(aes_key, derived))
            eph_pk_bytes = eph_sk.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            combined = len(eph_pk_bytes).to_bytes(4, 'big') + eph_pk_bytes + enc_key + ct
        b64 = base64.b64encode(combined).decode()
        return VexarScript.encode(b64.encode().hex()) if use_alien else b64
    
    @classmethod
    def decrypt_text(cls, text, private_key, use_alien: bool = True):
        try:
            if use_alien:
                h = VexarScript.decode(text)
                if not h: return None
                b64 = bytes.fromhex(h).decode()
            else:
                b64 = text
            if isinstance(private_key, bytes):
                private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
            combined = base64.b64decode(b64)
            prefix_len = int.from_bytes(combined[:4], 'big')
            if hasattr(private_key, 'curve'):
                eph_pk = serialization.load_pem_public_key(combined[4:4+prefix_len], backend=default_backend())
                shared = private_key.exchange(ec.ECDH(), eph_pk)
                derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'enc', backend=default_backend()).derive(shared)
                enc_key = combined[4+prefix_len:4+prefix_len+32]
                ct = combined[4+prefix_len+32:]
                aes_key = bytes(a ^ b for a, b in zip(enc_key, derived))
            elif hasattr(private_key, 'decrypt'):
                enc_key = combined[4:4+prefix_len]
                ct = combined[4+prefix_len:]
                aes_key = private_key.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            else:
                eph_pk_bytes = combined[4:4+prefix_len]
                eph_pk = X25519PublicKey.from_public_bytes(eph_pk_bytes)
                x25519_sk = cls._ed_to_x25519_priv(private_key)
                shared = x25519_sk.exchange(eph_pk)
                derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'enc', backend=default_backend()).derive(shared)
                enc_key = combined[4+prefix_len:4+prefix_len+32]
                ct = combined[4+prefix_len+32:]
                aes_key = bytes(a ^ b for a, b in zip(enc_key, derived))
            return AESCrypto.decrypt_text(ct.decode(), aes_key, use_alien=False)
        except:
            return None
    
    @classmethod
    def encrypt_file(cls, filepath, public_key):
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
        with open(filepath, 'rb') as f: data = f.read()
        aes_key = secrets.token_bytes(32)
        ct = AESCrypto.encrypt_file(filepath, aes_key)
        enc_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return len(enc_key).to_bytes(4, 'big') + enc_key + ct
    
    @classmethod
    def decrypt_file(cls, data, private_key):
        if isinstance(private_key, bytes):
            private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        prefix_len = int.from_bytes(data[:4], 'big')
        enc_key = data[4:4+prefix_len]
        ct = data[4+prefix_len:]
        aes_key = private_key.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return AESCrypto.decrypt_file(ct, aes_key)


class WorkerThread(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
    
    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args
    
    def run(self):
        try:
            result = self.func(*self.args)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class AlienEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Alien Encryption")
        self.setWindowIcon(QIcon("icon.png"))
        self.setMinimumSize(950, 720)
        
        self.aes_key = None
        self.aes_salt = None
        self.rsa_private = None
        self.rsa_public = None
        self.rsa_private_pem = None
        self.rsa_public_pem = None
        self.current_rsa_type = 'rsa'
        self.alien_script_enabled = True
        self.dark_mode = True
        self.pw_visible = False
        self.one_time_enabled = False
        
        self.setup_ui()
        self.apply_theme()
        self.center()
    
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(20, 16, 20, 16)
        main_layout.setSpacing(12)
        
        # Header
        header = QFrame()
        header.setObjectName("header")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(20, 16, 20, 16)
        
        title_row = QHBoxLayout()
        title = QLabel("🛸 Alien Encryption")
        title.setObjectName("title")
        title_row.addWidget(title)
        title_row.addStretch()
        
        self.alien_btn = QPushButton("👽 Alien: ON")
        self.alien_btn.setObjectName("primaryBtn")
        self.alien_btn.clicked.connect(self.toggle_alien)
        self.alien_btn.setFixedWidth(130)
        self.alien_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        title_row.addWidget(self.alien_btn)
        
        self.theme_btn = QPushButton("☀️ Light")
        self.theme_btn.setObjectName("secondaryBtn")
        self.theme_btn.clicked.connect(self.toggle_theme)
        self.theme_btn.setFixedWidth(100)
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        title_row.addWidget(self.theme_btn)
        
        header_layout.addLayout(title_row)
        header_layout.addWidget(QLabel("AES-256-GCM | RSA | EC | Ed25519", objectName="subtitle"))
        main_layout.addWidget(header)
        
        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        main_layout.addWidget(self.tabs)
        
        self.aes_tab = self.create_aes_tab()
        self.rsa_tab = self.create_rsa_tab()
        self.tabs.addTab(self.aes_tab, "  🔐 AES-256  ")
        self.tabs.addTab(self.rsa_tab, "  🔑 Asymmetric  ")
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setObjectName("progressBar")
        self.progress.setVisible(False)
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        main_layout.addWidget(self.progress)
        
        # Status
        self.status = QLabel("Ready")
        self.status.setObjectName("status")
        main_layout.addWidget(self.status)
    
    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.theme_btn.setText("🌙 Dark" if not self.dark_mode else "☀️ Light")
        self.apply_theme()
    
    def toggle_alien(self):
        self.alien_script_enabled = not self.alien_script_enabled
        self.alien_btn.setText(f"👽 Alien: {'ON' if self.alien_script_enabled else 'OFF'}")
        self.alien_btn.setObjectName("primaryBtn" if self.alien_script_enabled else "secondaryBtn")
        self.apply_theme()
        self.set_status(f"Alien script {'enabled' if self.alien_script_enabled else 'disabled'}", "#0a0" if self.alien_script_enabled else "#888")
    
    def create_card(self):
        card = QFrame()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)
        return card, layout
    
    def create_aes_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)
        
        # Key card
        kc, kl = self.create_card()
        kl.addWidget(QLabel("🔑 Encryption Key", objectName="cardTitle"))
        kr = QHBoxLayout()
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.aes_key_input.setPlaceholderText("Password or hex key...")
        kr.addWidget(self.aes_key_input)
        
        self.eye_btn = QPushButton("👁"); self.eye_btn.setObjectName("smallBtn"); self.eye_btn.clicked.connect(self.toggle_pw); self.eye_btn.setFixedWidth(40); self.eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        kr.addWidget(self.eye_btn)
        for t, f in [("📥", self.paste_aes), ("🎲", self.gen_aes), ("📋", lambda: self.cp(self.aes_key_input.text()))]:
            b = QPushButton(t); b.setObjectName("secondaryBtn"); b.clicked.connect(f); b.setCursor(Qt.CursorShape.PointingHandCursor); kr.addWidget(b)
        kl.addLayout(kr)
        
        # One-time checkbox
        self.one_time_cb = QCheckBox("🔒 One-time decryption (message can only be decrypted once)")
        self.one_time_cb.setObjectName("cardTitle")
        self.one_time_cb.toggled.connect(self.on_one_time_toggle)
        kl.addWidget(self.one_time_cb)
        
        layout.addWidget(kc)
        
        # Text areas
        tl = QHBoxLayout()
        for n, ti, ro in [("ai", "📝 Input", False), ("ao", "🔮 Output", True)]:
            c, cl = self.create_card()
            h = QHBoxLayout()
            h.addWidget(QLabel(ti, objectName="cardTitle" if not ro else "cardTitlePurple"))
            h.addStretch()
            if ro:
                cb = QPushButton("📋 Copy"); cb.setObjectName("smallBtn"); cb.clicked.connect(self.copy_aes_out); cb.setCursor(Qt.CursorShape.PointingHandCursor); h.addWidget(cb)
            cl.addLayout(h)
            te = QTextEdit(); te.setPlaceholderText("Enter text..." if not ro else "Result..."); te.setReadOnly(ro); cl.addWidget(te)
            setattr(self, n, te); tl.addWidget(c)
        layout.addLayout(tl, 1)
        
        # Buttons
        bl = QHBoxLayout()
        for t, f, p in [("🔒 Encrypt", self.aes_enc, True), ("🔓 Decrypt", self.aes_dec, False), ("⇄ Swap", self.aes_swap, False), ("📁 Encrypt File", self.aes_enc_file, False), ("📁 Decrypt File", self.aes_dec_file, False)]:
            b = QPushButton(t); b.setObjectName("primaryBtn" if p else "secondaryBtn"); b.clicked.connect(f); b.setCursor(Qt.CursorShape.PointingHandCursor); bl.addWidget(b)
        layout.addLayout(bl)
        return tab
    
    def create_rsa_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)
        
        # Config
        cc, cl = self.create_card()
        ktr = QHBoxLayout(); ktr.addWidget(QLabel("🔧 Key Type:"))
        self.kg = QButtonGroup()
        for n, c in [("RSA", True), ("EC", False), ("Ed25519", False)]:
            r = QRadioButton(n); r.setChecked(c); r.toggled.connect(self.on_kt); self.kg.addButton(r); ktr.addWidget(r)
        ktr.addStretch(); cl.addLayout(ktr)
        pr = QHBoxLayout()
        self.kpl = QLabel("📏 Key Size:"); pr.addWidget(self.kpl)
        self.kpc = QComboBox(); self.kpc.addItems(["2048","3072","4096","8192"]); pr.addWidget(self.kpc)
        for t, f, p in [("🎲 Generate", self.gen_rsa, True), ("📥 Import", self.imp_rsa, False), ("💾 Save Keys", self.save_rsa, False)]:
            b = QPushButton(t); b.setObjectName("primaryBtn" if p else "secondaryBtn"); b.clicked.connect(f); b.setCursor(Qt.CursorShape.PointingHandCursor); pr.addWidget(b)
        pr.addStretch(); cl.addLayout(pr); layout.addWidget(cc)
        
        # Keys
        kc, kl = self.create_card()
        for lb, co, fn in [("🔓 Public Key", "cardTitleGreen", "rp"), ("🔒 Private Key", "cardTitleRed", "rk")]:
            kl.addWidget(QLabel(lb, objectName=co))
            row = QHBoxLayout(); le = QLineEdit(); le.setReadOnly(True); setattr(self, fn, le); row.addWidget(le)
            for ic, cbf in [("📋", lambda f=le: self.cp(f.text())), ("📥", lambda f=le: self.pf(f))]:
                b = QPushButton(ic); b.setObjectName("smallBtn"); b.clicked.connect(cbf); b.setFixedWidth(45); b.setCursor(Qt.CursorShape.PointingHandCursor); row.addWidget(b)
            kl.addLayout(row)
        layout.addWidget(kc)
        
        # Text areas
        tl = QHBoxLayout()
        for n, ti, ro in [("ri", "📝 Input", False), ("ro", "🔮 Output", True)]:
            c, cl = self.create_card()
            h = QHBoxLayout()
            h.addWidget(QLabel(ti, objectName="cardTitle" if not ro else "cardTitlePurple"))
            h.addStretch()
            if ro:
                cb = QPushButton("📋 Copy"); cb.setObjectName("smallBtn"); cb.clicked.connect(self.copy_rsa_out); cb.setCursor(Qt.CursorShape.PointingHandCursor); h.addWidget(cb)
            cl.addLayout(h)
            te = QTextEdit(); te.setPlaceholderText("Enter text..." if not ro else "Result..."); te.setReadOnly(ro); cl.addWidget(te)
            setattr(self, n, te); tl.addWidget(c)
        layout.addLayout(tl, 1)
        
        # Buttons
        bl = QHBoxLayout()
        for t, f, p in [("🔒 Encrypt", self.rsa_enc, True), ("🔓 Decrypt", self.rsa_dec, False), ("⇄ Swap", self.rsa_swap, False), ("📁 Encrypt File", self.rsa_enc_file, False), ("📁 Decrypt File", self.rsa_dec_file, False)]:
            b = QPushButton(t); b.setObjectName("primaryBtn" if p else "secondaryBtn"); b.clicked.connect(f); b.setCursor(Qt.CursorShape.PointingHandCursor); bl.addWidget(b)
        layout.addLayout(bl)
        return tab
    
    def on_kt(self):
        for r in self.kg.buttons():
            if r.isChecked(): t = r.text()
        if t == "RSA": self.current_rsa_type = 'rsa'; self.kpl.setText("📏 Key Size:"); self.kpc.clear(); self.kpc.addItems(["2048","3072","4096","8192"])
        elif t == "EC": self.current_rsa_type = 'ec'; self.kpl.setText("📐 Curve:"); self.kpc.clear(); self.kpc.addItems(["secp256r1 (P-256)","secp384r1 (P-384)","secp521r1 (P-521)"])
        else: self.current_rsa_type = 'ed25519'; self.kpl.setText("📐 Algorithm:"); self.kpc.clear(); self.kpc.addItems(["Ed25519"])
    
    def on_one_time_toggle(self, checked):
        self.one_time_enabled = checked
        if checked:
            self.set_status("⚠️ One-time decryption enabled - message can only be decrypted once", "#ffa500")
        else:
            self.set_status("✅ Normal encryption mode", "#0a0")
    
    def apply_theme(self):
        d = self.dark_mode
        style = f"""
        * {{ font-family: 'Segoe UI', sans-serif; font-size: 13px; }}
        QMainWindow {{ background-color: {'#0d0d1a' if d else '#f0f0f0'}; }}
        QWidget {{ color: {'#e8e8f0' if d else '#222'}; }}
        #header {{ background-color: {'#1a1a30' if d else '#ffffff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 12px; }}
        #title {{ font-size: 24px; font-weight: bold; color: {'#00d4aa' if d else '#007755'}; background: transparent; }}
        #subtitle {{ font-size: 11px; color: {'#888' if d else '#777'}; background: transparent; }}
        #mainTabs {{ background-color: transparent; }}
        #mainTabs::pane {{ border: none; background: transparent; }}
        QTabBar::tab {{ background-color: {'#1a1a30' if d else '#ffffff'}; color: {'#e0e0e0' if d else '#333'}; padding: 10px 20px; margin-right: 4px; border-radius: 8px 8px 0 0; font-weight: bold; border: 1px solid {'#2a2a45' if d else '#ccc'}; }}
        QTabBar::tab:selected {{ background-color: {'#00d4aa' if d else '#007755'}; color: {'#0d0d1a' if d else '#fff'}; }}
        QTabBar::tab:hover:!selected {{ background-color: {'#252540' if d else '#e8e8e8'}; }}
        #card {{ background-color: {'#1a1a30' if d else '#ffffff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 10px; }}
        #cardTitle {{ font-size: 14px; font-weight: bold; color: {'#e8e8f0' if d else '#222'}; background: transparent; }}
        #cardTitlePurple {{ font-size: 14px; font-weight: bold; color: {'#c084fc' if d else '#5500aa'}; background: transparent; }}
        #cardTitleGreen {{ font-size: 14px; font-weight: bold; color: {'#00d4aa' if d else '#007755'}; background: transparent; }}
        #cardTitleRed {{ font-size: 14px; font-weight: bold; color: {'#ff6b6b' if d else '#aa0000'}; background: transparent; }}
        QLineEdit {{ background-color: {'#12122a' if d else '#ffffff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 6px; padding: 8px 12px; color: {'#e8e8f0' if d else '#222'}; font-family: 'Consolas', monospace; font-size: 12px; }}
        QLineEdit:focus {{ border-color: {'#00d4aa' if d else '#007755'}; }}
        QTextEdit {{ background-color: {'#12122a' if d else '#ffffff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 6px; padding: 10px; color: {'#e8e8f0' if d else '#222'}; }}
        QTextEdit:focus {{ border-color: {'#00d4aa' if d else '#007755'}; }}
        QPushButton {{ background-color: {'#252540' if d else '#e0e0e0'}; color: {'#e8e8f0' if d else '#222'}; border: none; border-radius: 6px; padding: 8px 16px; font-weight: bold; font-size: 12px; }}
        QPushButton:hover {{ background-color: {'#2d2d50' if d else '#d0d0d0'}; }}
        #primaryBtn {{ background-color: {'#00d4aa' if d else '#007755'}; color: {'#0d0d1a' if d else '#fff'}; }}
        #primaryBtn:hover {{ background-color: {'#00e6b8' if d else '#005544'}; }}
        #secondaryBtn {{ background-color: {'#252540' if d else '#e0e0e0'}; color: {'#e8e8f0' if d else '#222'}; }}
        #secondaryBtn:hover {{ background-color: {'#2d2d50' if d else '#d0d0d0'}; }}
        #smallBtn {{ padding: 4px 10px; font-size: 11px; min-width: 40px; max-width: 50px; }}
        QCheckBox {{ color: {'#e8e8f0' if d else '#222'}; spacing: 8px; background: transparent; }}
        QCheckBox::indicator {{ width: 20px; height: 20px; border-radius: 4px; border: 2px solid {'#2a2a45' if d else '#aaa'}; background-color: {'#12122a' if d else '#fff'}; }}
        QCheckBox::indicator:checked {{ border-color: {'#00d4aa' if d else '#007755'}; background-color: {'#00d4aa' if d else '#007755'}; }}
        QRadioButton {{ color: {'#e8e8f0' if d else '#222'}; spacing: 8px; background: transparent; }}
        QRadioButton::indicator {{ width: 18px; height: 18px; border-radius: 9px; border: 2px solid {'#2a2a45' if d else '#aaa'}; background-color: {'#12122a' if d else '#fff'}; }}
        QRadioButton::indicator:checked {{ border-color: {'#00d4aa' if d else '#007755'}; background-color: {'#00d4aa' if d else '#007755'}; }}
        QComboBox {{ background-color: {'#12122a' if d else '#fff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 6px; padding: 8px 12px; color: {'#e8e8f0' if d else '#222'}; font-size: 12px; min-width: 160px; }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox::down-arrow {{ image: none; border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 6px solid {'#e8e8f0' if d else '#333'}; margin-right: 8px; }}
        QComboBox QAbstractItemView {{ background-color: {'#1a1a30' if d else '#fff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; color: {'#e8e8f0' if d else '#222'}; selection-background-color: {'#00d4aa' if d else '#007755'}; selection-color: {'#0d0d1a' if d else '#fff'}; }}
        #progressBar {{ background-color: {'#12122a' if d else '#e8e8e8'}; border: none; border-radius: 4px; height: 6px; }}
        #progressBar::chunk {{ background-color: {'#00d4aa' if d else '#007755'}; border-radius: 4px; }}
        #status {{ font-size: 11px; color: {'#888' if d else '#777'}; padding: 4px 0; background: transparent; }}
        QLabel {{ background: transparent; }}
        """
        self.setStyleSheet(style)
    
    def run_thread(self, func, *args, on_finish=None, status=None, progress_cb=None):
        if status: self.set_status(status, "#2196f3")
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.thread = WorkerThread(func, *args)
        if on_finish: self.thread.finished.connect(on_finish)
        self.thread.finished.connect(lambda _: self.progress.setVisible(False))
        self.thread.error.connect(lambda e: (self.set_status(f"Error: {e}", "red"), self.progress.setVisible(False)))
        if progress_cb: self.thread.progress.connect(progress_cb)
        self.thread.start()
    
    def toggle_pw(self):
        self.pw_visible = not self.pw_visible
        self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Normal if self.pw_visible else QLineEdit.EchoMode.Password)
        self.eye_btn.setText("🙈" if self.pw_visible else "👁")
    
    def paste_aes(self):
        t = QApplication.clipboard().text()
        if t: self.aes_key_input.setText(t.strip())
    
    def gen_aes(self):
        self.aes_key = AESCrypto.generate_key()
        self.aes_key_input.setText(self.aes_key.hex())
        self.aes_salt = None
    
    def get_aes_key(self):
        k = self.aes_key_input.text().strip()
        if not k: QMessageBox.warning(self, "Error", "Enter password or key"); return None
        try:
            key = bytes.fromhex(k)
            if len(key) == 32: self.aes_key = key; return key
        except: pass
        if self.aes_salt: self.aes_key, _ = AESCrypto.derive_key(k, self.aes_salt)
        else: self.aes_key, self.aes_salt = AESCrypto.derive_key(k)
        return self.aes_key
    
    def aes_enc(self):
        t = self.ai.toPlainText().strip()
        if not t: return QMessageBox.warning(self, "Warning", "Enter text")
        k = self.get_aes_key()
        if not k: return
        self.run_thread(AESCrypto.encrypt_text, t, k, self.alien_script_enabled, self.one_time_enabled, on_finish=lambda r: self.ao.setPlainText(r), status="Encrypting...")
    
    def aes_dec(self):
        t = self.ai.toPlainText().strip()
        if not t: return QMessageBox.warning(self, "Warning", "Paste encrypted text")
        k = self.get_aes_key()
        if not k: return
        def cb(r):
            if r: self.ao.setPlainText(r)
            else: self.set_status("Invalid key or data", "red")
        self.run_thread(AESCrypto.decrypt_text, t, k, self.alien_script_enabled, on_finish=cb, status="Decrypting...")
    
    def aes_swap(self):
        i = self.ai.toPlainText(); o = self.ao.toPlainText()
        self.ai.setPlainText(o); self.ao.setPlainText(i)
    
    def aes_enc_file(self):
        k = self.get_aes_key()
        if not k: return
        fp, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not fp: return
        def update_progress(v): self.progress.setValue(v)
        def task(): return AESCrypto.encrypt_file(fp, k, progress_callback=update_progress)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ".enc"), status="Encrypting file...", progress_cb=update_progress)
    
    def aes_dec_file(self):
        k = self.get_aes_key()
        if not k: return
        fp, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not fp: return
        def update_progress(v): self.progress.setValue(v)
        def task():
            with open(fp, 'rb') as f: data = f.read()
            return AESCrypto.decrypt_file(data, k, progress_callback=update_progress)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ""), status="Decrypting file...", progress_cb=update_progress)
    
    def _save_file(self, data, original_path, ext):
        base = os.path.basename(original_path).replace('.enc', '')
        sp, _ = QFileDialog.getSaveFileName(self, "Save file", base + ext)
        if sp:
            with open(sp, 'wb') as f: f.write(data)
            self.set_status(f"Saved: {os.path.basename(sp)}", "#0a0")
    
    def copy_aes_out(self):
        t = self.ao.toPlainText()
        if t: self.cp(t)
    
    def gen_rsa(self):
        kp = self.kpc.currentText()
        if self.current_rsa_type == 'rsa': f, a = RSACrypto.generate_rsa, (int(kp.split()[0]),)
        elif self.current_rsa_type == 'ec': f, a = RSACrypto.generate_ec, (kp.split()[0],)
        else: f, a = RSACrypto.generate_ed25519, ()
        def cb(r):
            self.rsa_private_pem, self.rsa_public_pem, self.rsa_private, self.rsa_public = r
            self.rk.setText(r[0].decode()); self.rp.setText(r[1].decode())
            self.set_status("Keys generated", "#0a0")
        self.run_thread(f, *a, on_finish=cb, status="Generating keys...")
    
    def imp_rsa(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Import Key", filter="PEM files (*.pem);;All files (*.*)")
        if not fp: return
        try:
            with open(fp, 'rb') as f: pem = f.read()
            self.rsa_private, self.rsa_public, pp = RSACrypto.load_private(pem)
            self.rsa_private_pem, self.rsa_public_pem = pem, pp
            self.rk.setText(pem.decode()); self.rp.setText(pp.decode())
            self.set_status("Key imported", "#0a0")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))
    
    def save_rsa(self):
        if not self.rsa_private_pem: return QMessageBox.warning(self, "Error", "Generate keys first")
        d = QFileDialog.getExistingDirectory(self, "Select folder")
        if not d: return
        with open(os.path.join(d, "private_key.pem"), 'wb') as f: f.write(self.rsa_private_pem)
        with open(os.path.join(d, "public_key.pem"), 'wb') as f: f.write(self.rsa_public_pem)
        QMessageBox.information(self, "Saved", f"Keys saved to {d}")
    
    def pf(self, f):
        t = QApplication.clipboard().text()
        if t: f.setText(t.strip())
    
    def get_rsa_keys(self):
        if not self.rsa_public_pem: QMessageBox.warning(self, "Error", "Generate or import keys"); return None, None
        return self.rsa_private, self.rsa_public
    
    def rsa_enc(self):
        t = self.ri.toPlainText().strip()
        if not t: return QMessageBox.warning(self, "Warning", "Enter text")
        _, pk = self.get_rsa_keys()
        if not pk: return
        self.run_thread(RSACrypto.encrypt_text, t, pk, self.alien_script_enabled, self.one_time_enabled, on_finish=lambda r: self.ro.setPlainText(r), status="Encrypting...")
    
    def rsa_dec(self):
        t = self.ri.toPlainText().strip()
        if not t: return QMessageBox.warning(self, "Warning", "Paste encrypted text")
        sk, _ = self.get_rsa_keys()
        if not sk: return
        def cb(r):
            if r: self.ro.setPlainText(r)
            else: self.set_status("Invalid key or data", "red")
        self.run_thread(RSACrypto.decrypt_text, t, sk, self.alien_script_enabled, on_finish=cb, status="Decrypting...")
    
    def rsa_swap(self):
        i = self.ri.toPlainText(); o = self.ro.toPlainText()
        self.ri.setPlainText(o); self.ro.setPlainText(i)
    
    def rsa_enc_file(self):
        _, pk = self.get_rsa_keys()
        if not pk: return
        fp, _ = QFileDialog.getOpenFileName(self, "Select file to encrypt")
        if not fp: return
        def task(): return RSACrypto.encrypt_file(fp, pk)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ".enc"), status="Encrypting file...")
    
    def rsa_dec_file(self):
        sk, _ = self.get_rsa_keys()
        if not sk: return
        fp, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not fp: return
        def task():
            with open(fp, 'rb') as f: return RSACrypto.decrypt_file(f.read(), sk)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ""), status="Decrypting file...")
    
    def copy_rsa_out(self):
        t = self.ro.toPlainText()
        if t: self.cp(t)
    
    def cp(self, text):
        if text: QApplication.clipboard().setText(text)
    
    def set_status(self, msg, color="#888"):
        self.status.setText(msg)
        self.status.setStyleSheet(f"color: {color}; font-size: 11px; background: transparent;")
    
    def center(self):
        screen = QApplication.primaryScreen()
        if screen:
            geo = screen.availableGeometry()
            self.resize(1000, 750)
            x = (geo.width() - self.width()) // 2 + geo.x()
            y = (geo.height() - self.height()) // 2 + geo.y()
            self.move(x, y)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AlienEncryptionApp()
    window.show()
    sys.exit(app.exec())
