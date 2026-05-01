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
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QThread, QBuffer
from PyQt6.QtGui import QFont, QScreen, QIcon, QPixmap, QPainter, QColor, QBrush, QPen, QImage

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

# Try to import QR code libraries
try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

try:
    from pyzbar.pyzbar import decode as qr_decode
    QR_DECODE_AVAILABLE = True
except ImportError:
    QR_DECODE_AVAILABLE = False


# ==================== BASE64 ICON PLACEHOLDER ====================
# Replace this string with your own base64-encoded PNG/ICO image
# To convert your image to base64:
# python -c "import base64; print(base64.b64encode(open('your_icon.png','rb').read()).decode())"

APP_ICON_BASE64 = """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"""


def load_icon_from_base64(b64_string: str) -> QIcon:
    """Load QIcon from base64 string"""
    if not b64_string or not b64_string.strip():
        return QIcon()
    
    try:
        image_bytes = base64.b64decode(b64_string.strip())
        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes)
        if not pixmap.isNull():
            return QIcon(pixmap)
    except:
        pass
    
    return QIcon()


# ==================== VEXAR ALIEN SCRIPT ====================

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


# ==================== QR CODE UTILS ====================

class QRUtils:
    @staticmethod
    def text_to_qr_image(text: str, size: int = 400) -> QPixmap:
        if not QR_AVAILABLE:
            return None
        qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img = img.resize((size, size), Image.Resampling.LANCZOS)
        img.save("_temp_qr.png")
        pixmap = QPixmap("_temp_qr.png")
        os.remove("_temp_qr.png")
        return pixmap
    
    @staticmethod
    def qr_image_to_text(filepath: str) -> Optional[str]:
        if not QR_DECODE_AVAILABLE:
            return None
        from PIL import Image
        img = Image.open(filepath)
        decoded = qr_decode(img)
        if decoded:
            return decoded[0].data.decode('utf-8')
        return None


# ==================== CRYPTO ENGINES ====================

class AESCrypto:
    NONCE_LEN = 12
    CHUNK_SIZE = 64 * 1024 * 1024
    
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
        prefix = b"\x01" if one_time else b"\x00"
        result = prefix + result
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
        file_size = os.path.getsize(filepath)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'file-encryption', backend=default_backend())
        key_material = hkdf.derive(key)
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        
        result = bytearray()
        result.extend(b"AESGCM_CHUNKED")
        result.extend(secrets.token_bytes(16))
        
        chunk_index = 0
        processed = 0
        
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(cls.CHUNK_SIZE)
                if not chunk: break
                chunk_info = chunk_index.to_bytes(8, 'big')
                chunk_kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=mac_key, info=chunk_info, backend=default_backend())
                chunk_key = chunk_kdf.derive(enc_key)
                nonce = hashlib.sha256(chunk_info + key).digest()[:12]
                aesgcm = AESGCM(chunk_key)
                ct = aesgcm.encrypt(nonce, chunk, chunk_info)
                result.extend(chunk_index.to_bytes(8, 'big'))
                result.extend(nonce)
                result.extend(ct)
                chunk_index += 1
                processed += len(chunk)
                if progress_callback:
                    progress_callback(int(processed * 100 / file_size))
        
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(bytes(result))
        result.extend(h.finalize())
        return bytes(result)
    
    @classmethod
    def decrypt_file(cls, data: bytes, key: bytes, progress_callback=None) -> bytes:
        mac_tag = data[-32:]
        payload = data[:-32]
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'file-encryption', backend=default_backend())
        key_material = hkdf.derive(key)
        enc_key = key_material[:32]
        mac_key = key_material[32:]
        
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(payload)
        try: h.verify(mac_tag)
        except: raise ValueError("File integrity check failed")
        
        chunk_data = payload[32:]
        result = bytearray()
        offset = 0
        total_size = len(chunk_data)
        
        while offset < total_size:
            chunk_index = int.from_bytes(chunk_data[offset:offset+8], 'big')
            offset += 8
            nonce = chunk_data[offset:offset+12]
            offset += 12
            chunk_info = chunk_index.to_bytes(8, 'big')
            chunk_kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=mac_key, info=chunk_info, backend=default_backend())
            chunk_key = chunk_kdf.derive(enc_key)
            aesgcm = AESGCM(chunk_key)
            ct = chunk_data[offset:]
            plaintext = aesgcm.decrypt(nonce, ct, chunk_info)
            result.extend(plaintext)
            if progress_callback: progress_callback(100)
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
            else: b64 = text
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
        except: return None
    
    @classmethod
    def encrypt_file(cls, filepath, public_key):
        if isinstance(public_key, bytes):
            public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
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
        self.setWindowIcon(load_icon_from_base64(APP_ICON_BASE64))
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
        header_layout.addWidget(QLabel("AES-256-GCM | RSA | EC | Ed25519 | QR Support", objectName="subtitle"))
        main_layout.addWidget(header)
        
        self.tabs = QTabWidget()
        self.tabs.setObjectName("mainTabs")
        main_layout.addWidget(self.tabs)
        
        self.aes_tab = self.create_aes_tab()
        self.rsa_tab = self.create_rsa_tab()
        self.tabs.addTab(self.aes_tab, "  🔐 AES-256  ")
        self.tabs.addTab(self.rsa_tab, "  🔑 Asymmetric  ")
        
        self.progress = QProgressBar()
        self.progress.setObjectName("progressBar")
        self.progress.setVisible(False)
        self.progress.setMinimum(0)
        self.progress.setMaximum(100)
        main_layout.addWidget(self.progress)
        
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
        
        kc, kl = self.create_card()
        kl.addWidget(QLabel("🔑 Encryption Key", objectName="cardTitle"))
        kr = QHBoxLayout()
        self.aes_key_input = QLineEdit()
        self.aes_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.aes_key_input.setPlaceholderText("Password or hex key...")
        kr.addWidget(self.aes_key_input)
        
        self.eye_btn = QPushButton("👁")
        self.eye_btn.setObjectName("smallBtn")
        self.eye_btn.clicked.connect(self.toggle_pw)
        self.eye_btn.setFixedWidth(40)
        self.eye_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        kr.addWidget(self.eye_btn)
        
        for t, f in [("📥", self.paste_aes), ("🎲", self.gen_aes), ("📋", lambda: self.cp(self.aes_key_input.text()))]:
            b = QPushButton(t)
            b.setObjectName("secondaryBtn")
            b.clicked.connect(f)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            kr.addWidget(b)
        kl.addLayout(kr)
        
        self.one_time_cb = QCheckBox("🔒 One-time decryption")
        self.one_time_cb.toggled.connect(self.on_one_time_toggle)
        kl.addWidget(self.one_time_cb)
        layout.addWidget(kc)
        
        tl = QHBoxLayout()
        for n, ti, ro in [("ai", "📝 Input", False), ("ao", "🔮 Output", True)]:
            c, cl = self.create_card()
            h = QHBoxLayout()
            h.addWidget(QLabel(ti, objectName="cardTitle" if not ro else "cardTitlePurple"))
            h.addStretch()
            if ro:
                cb = QPushButton("📋 Copy")
                cb.setObjectName("smallBtn")
                cb.clicked.connect(self.copy_aes_out)
                cb.setCursor(Qt.CursorShape.PointingHandCursor)
                h.addWidget(cb)
                if QR_AVAILABLE:
                    qr_btn = QPushButton("📱 QR")
                    qr_btn.setObjectName("smallBtn")
                    qr_btn.clicked.connect(self.export_qr_aes)
                    qr_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                    h.addWidget(qr_btn)
            cl.addLayout(h)
            te = QTextEdit()
            te.setPlaceholderText("Enter text..." if not ro else "Result...")
            te.setReadOnly(ro)
            cl.addWidget(te)
            setattr(self, n, te)
            tl.addWidget(c)
        layout.addLayout(tl, 1)
        
        bl = QHBoxLayout()
        for t, f, p in [("🔒 Encrypt", self.aes_enc, True), ("🔓 Decrypt", self.aes_dec, False), ("⇄ Swap", self.aes_swap, False), ("📱 QR Decrypt", self.qr_decrypt_aes, False), ("📁 Encrypt File", self.aes_enc_file, False), ("📁 Decrypt File", self.aes_dec_file, False)]:
            b = QPushButton(t)
            b.setObjectName("primaryBtn" if p else "secondaryBtn")
            b.clicked.connect(f)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            bl.addWidget(b)
        layout.addLayout(bl)
        return tab
    
    def create_rsa_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 8, 0, 0)
        layout.setSpacing(10)
        
        cc, cl = self.create_card()
        ktr = QHBoxLayout()
        ktr.addWidget(QLabel("🔧 Key Type:"))
        self.kg = QButtonGroup()
        for n, c in [("RSA", True), ("EC", False), ("Ed25519", False)]:
            r = QRadioButton(n)
            r.setChecked(c)
            r.toggled.connect(self.on_kt)
            self.kg.addButton(r)
            ktr.addWidget(r)
        ktr.addStretch()
        cl.addLayout(ktr)
        
        pr = QHBoxLayout()
        self.kpl = QLabel("📏 Key Size:")
        pr.addWidget(self.kpl)
        self.kpc = QComboBox()
        self.kpc.addItems(["2048","3072","4096","8192"])
        pr.addWidget(self.kpc)
        for t, f, p in [("🎲 Generate", self.gen_rsa, True), ("📥 Import", self.imp_rsa, False), ("💾 Save Keys", self.save_rsa, False)]:
            b = QPushButton(t)
            b.setObjectName("primaryBtn" if p else "secondaryBtn")
            b.clicked.connect(f)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            pr.addWidget(b)
        pr.addStretch()
        cl.addLayout(pr)
        layout.addWidget(cc)
        
        kc, kl = self.create_card()
        for lb, co, fn in [("🔓 Public Key", "cardTitleGreen", "rp"), ("🔒 Private Key", "cardTitleRed", "rk")]:
            kl.addWidget(QLabel(lb, objectName=co))
            row = QHBoxLayout()
            le = QLineEdit()
            le.setReadOnly(True)
            setattr(self, fn, le)
            row.addWidget(le)
            for ic, cbf in [("📋", lambda f=le: self.cp(f.text())), ("📥", lambda f=le: self.pf(f))]:
                b = QPushButton(ic)
                b.setObjectName("smallBtn")
                b.clicked.connect(cbf)
                b.setFixedWidth(45)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                row.addWidget(b)
            kl.addLayout(row)
        layout.addWidget(kc)
        
        tl = QHBoxLayout()
        for n, ti, ro in [("ri", "📝 Input", False), ("ro", "🔮 Output", True)]:
            c, cl = self.create_card()
            h = QHBoxLayout()
            h.addWidget(QLabel(ti, objectName="cardTitle" if not ro else "cardTitlePurple"))
            h.addStretch()
            if ro:
                cb = QPushButton("📋 Copy")
                cb.setObjectName("smallBtn")
                cb.clicked.connect(self.copy_rsa_out)
                cb.setCursor(Qt.CursorShape.PointingHandCursor)
                h.addWidget(cb)
                if QR_AVAILABLE:
                    qr_btn = QPushButton("📱 QR")
                    qr_btn.setObjectName("smallBtn")
                    qr_btn.clicked.connect(self.export_qr_rsa)
                    qr_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                    h.addWidget(qr_btn)
            cl.addLayout(h)
            te = QTextEdit()
            te.setPlaceholderText("Enter text..." if not ro else "Result...")
            te.setReadOnly(ro)
            cl.addWidget(te)
            setattr(self, n, te)
            tl.addWidget(c)
        layout.addLayout(tl, 1)
        
        bl = QHBoxLayout()
        for t, f, p in [("🔒 Encrypt", self.rsa_enc, True), ("🔓 Decrypt", self.rsa_dec, False), ("⇄ Swap", self.rsa_swap, False), ("📱 QR Decrypt", self.qr_decrypt_rsa, False), ("📁 Encrypt File", self.rsa_enc_file, False), ("📁 Decrypt File", self.rsa_dec_file, False)]:
            b = QPushButton(t)
            b.setObjectName("primaryBtn" if p else "secondaryBtn")
            b.clicked.connect(f)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            bl.addWidget(b)
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
        self.set_status("⚠️ One-time decryption enabled" if checked else "Normal encryption mode", "#ffa500" if checked else "#0a0")
    
    def apply_theme(self):
        d = self.dark_mode
        style = f"""
        * {{ font-family: 'Segoe UI', sans-serif; font-size: 13px; }}
        QMainWindow {{ background-color: {'#0d0d1a' if d else '#f0f0f0'}; }}
        QWidget {{ color: {'#e8e8f0' if d else '#222'}; }}
        #header {{ background-color: {'#1a1a30' if d else '#ffffff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 12px; }}
        #title {{ font-size: 24px; font-weight: bold; color: {'#00d4aa' if d else '#007755'}; background: transparent; }}
        #subtitle {{ font-size: 11px; color: {'#888' if d else '#777'}; background: transparent; }}
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
        #smallBtn {{ padding: 4px 10px; font-size: 11px; min-width: 40px; max-width: 50px; }}
        QCheckBox {{ color: {'#e8e8f0' if d else '#222'}; spacing: 8px; background: transparent; }}
        QCheckBox::indicator {{ width: 20px; height: 20px; border-radius: 4px; border: 2px solid {'#2a2a45' if d else '#aaa'}; background-color: {'#12122a' if d else '#fff'}; }}
        QCheckBox::indicator:checked {{ border-color: {'#00d4aa' if d else '#007755'}; background-color: {'#00d4aa' if d else '#007755'}; }}
        QRadioButton {{ color: {'#e8e8f0' if d else '#222'}; spacing: 8px; background: transparent; }}
        QRadioButton::indicator {{ width: 18px; height: 18px; border-radius: 9px; border: 2px solid {'#2a2a45' if d else '#aaa'}; background-color: {'#12122a' if d else '#fff'}; }}
        QRadioButton::indicator:checked {{ border-color: {'#00d4aa' if d else '#007755'}; background-color: {'#00d4aa' if d else '#007755'}; }}
        QComboBox {{ background-color: {'#12122a' if d else '#fff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; border-radius: 6px; padding: 8px 12px; color: {'#e8e8f0' if d else '#222'}; font-size: 12px; min-width: 160px; }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox QAbstractItemView {{ background-color: {'#1a1a30' if d else '#fff'}; border: 1px solid {'#2a2a45' if d else '#ccc'}; color: {'#e8e8f0' if d else '#222'}; selection-background-color: {'#00d4aa' if d else '#007755'}; selection-color: {'#0d0d1a' if d else '#fff'}; }}
        #progressBar {{ background-color: {'#12122a' if d else '#e8e8e8'}; border: none; border-radius: 4px; height: 6px; }}
        #progressBar::chunk {{ background-color: {'#00d4aa' if d else '#007755'}; border-radius: 4px; }}
        #status {{ font-size: 11px; color: {'#888' if d else '#777'}; padding: 4px 0; background: transparent; }}
        QLabel {{ background: transparent; }}
        """
        self.setStyleSheet(style)
    
    def run_thread(self, func, *args, on_finish=None, status=None):
        if status: self.set_status(status, "#2196f3")
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.thread = WorkerThread(func, *args)
        if on_finish: self.thread.finished.connect(on_finish)
        self.thread.finished.connect(lambda _: self.progress.setVisible(False))
        self.thread.error.connect(lambda e: (self.set_status(f"Error: {e}", "red"), self.progress.setVisible(False)))
        self.thread.start()
    
    def export_qr_aes(self):
        text = self.ao.toPlainText().strip()
        if not text: return QMessageBox.warning(self, "Warning", "No output")
        self.export_qr(text)
    
    def export_qr_rsa(self):
        text = self.ro.toPlainText().strip()
        if not text: return QMessageBox.warning(self, "Warning", "No output")
        self.export_qr(text)
    
    def export_qr(self, text):
        if not QR_AVAILABLE:
            QMessageBox.critical(self, "Error", "Install: pip install qrcode[pil]")
            return
        fp, _ = QFileDialog.getSaveFileName(self, "Save QR Code", "encrypted_qr.png", "PNG (*.png)")
        if not fp: return
        try:
            pixmap = QRUtils.text_to_qr_image(text[:2000])
            if pixmap: pixmap.save(fp)
            self.set_status(f"QR saved: {os.path.basename(fp)}", "#0a0")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))
    
    def qr_decrypt_aes(self):
        k = self.get_aes_key()
        if not k: return
        text = self.decode_qr()
        if not text: return
        self.ai.setPlainText(text)
        self.aes_dec()
    
    def qr_decrypt_rsa(self):
        sk, _ = self.get_rsa_keys()
        if not sk: return
        text = self.decode_qr()
        if not text: return
        self.ri.setPlainText(text)
        self.rsa_dec()
    
    def decode_qr(self) -> Optional[str]:
        if not QR_DECODE_AVAILABLE:
            QMessageBox.critical(self, "Error", "Install: pip install pyzbar pillow")
            return None
        fp, _ = QFileDialog.getOpenFileName(self, "Open QR Code", filter="Images (*.png *.jpg *.bmp)")
        if not fp: return None
        try:
            text = QRUtils.qr_image_to_text(fp)
            if text:
                self.set_status("QR decoded", "#0a0")
                return text
            QMessageBox.warning(self, "Error", "No QR code found")
        except Exception as e: QMessageBox.critical(self, "Error", str(e))
        return None
    
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
        def up(v): self.progress.setValue(v)
        def task(): return AESCrypto.encrypt_file(fp, k, progress_callback=up)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ".enc"), status="Encrypting file...")
    
    def aes_dec_file(self):
        k = self.get_aes_key()
        if not k: return
        fp, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if not fp: return
        def up(v): self.progress.setValue(v)
        def task():
            with open(fp, 'rb') as f: data = f.read()
            return AESCrypto.decrypt_file(data, k, progress_callback=up)
        self.run_thread(task, on_finish=lambda d: self._save_file(d, fp, ""), status="Decrypting file...")
    
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
            self.move((geo.width() - self.width()) // 2 + geo.x(), (geo.height() - self.height()) // 2 + geo.y())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("Alien Encryption")
    app.setWindowIcon(load_icon_from_base64(APP_ICON_BASE64))
    window = AlienEncryptionApp()
    window.show()
    sys.exit(app.exec())
