import threading
import time
import os
import pyperclip
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from encryption import encrypt_data, generate_key, generate_hash, decrypt_data
from signature import generate_rsa_keys, sign_data, verify_signature

#
#EXISTENCIA DE SALT E PASSWORD POR TENTATIVA DE IMPLEMENTAÇÕES DE PONTOS EXTRAS
#DESCARTADOS POR FALTA DE TEMPO
#

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=1000000)

class ClipboardManager:
    def __init__(self, user_id, password='ola123', salt=None):
        self.user_id = user_id
        self.user_dir = f"user_data/{user_id}"
        os.makedirs(self.user_dir, exist_ok=True)
        if salt is None:
            self.salt = os.urandom(16)  # Gera um salt aleatório
        else:
            self.salt = salt.encode()
        self.key = generate_key() if not password else derive_key(password, self.salt)
        print(f"Key: {self.key.hex()}")
        self.private_key, self.public_key = self.load_or_generate_rsa_keys()
        self.history = []
        self.hashes = []
        self.running = True
        self.lock = threading.Lock()
        self.load_history(password)
        self.thread = threading.Thread(target=self.monitor_clipboard)
        self.thread.start()

    def load_or_generate_rsa_keys(self):
        private_key_path = f"{self.user_dir}/private_key.pem"
        public_key_path = f"{self.user_dir}/public_key.pem"
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            with open(private_key_path, 'rb') as f:
                private_key = f.read()
            with open(public_key_path, 'rb') as f:
                public_key = f.read()
        else:
            private_key, public_key = generate_rsa_keys()
            with open(private_key_path, 'wb') as f:
                f.write(private_key)
            with open(public_key_path, 'wb') as f:
                f.write(public_key)
        return private_key, public_key

    def monitor_clipboard(self):
        last_clipboard_content = ""
        start_time = time.time()
        while self.running:
            try:
                clipboard_content = pyperclip.paste()
                if clipboard_content != last_clipboard_content:
                    with self.lock:
                        self.history.append(clipboard_content)
                        self.hashes.append(generate_hash(clipboard_content))
                        last_clipboard_content = clipboard_content
                current_time = time.time()
                if current_time - start_time >= 300:  # 5 minutos
                    self.save_history()
                    start_time = current_time
                time.sleep(2)
            except Exception as e:
                print(f"Error reading clipboard content: {e}")

    def save_history(self):
        with self.lock:
            nonce, ciphertext, tag = encrypt_data('\n'.join(self.history), self.key)
            with open(f'{self.user_dir}/clipboard_history.enc', 'wb') as f:
                f.write(self.salt + nonce + ciphertext + tag)  # Inclui o salt no início do arquivo
            signature = sign_data(self.salt + nonce + ciphertext + tag, self.private_key)
            with open(f'{self.user_dir}/clipboard_history.sig', 'wb') as f:
                f.write(signature)
            with open(f'{self.user_dir}/clipboard_hashes.txt', 'w') as f:
                f.write('\n'.join(self.hashes))

    def load_history(self, password):
        try:
            with open(f'{self.user_dir}/clipboard_history.enc', 'rb') as f:
                data = f.read()
            salt_from_file = data[:16]  # Extraia o salt do início do arquivo
            nonce, ciphertext, tag = data[16:28], data[28:-16], data[-16:]
            
            # Derive the key using the extracted salt  
            key = derive_key(password, salt_from_file)
            #print(f"Derived Key: {key.hex()}")
            
            #print(f"Encrypted data length: {len(data)}")
            #print(f"Nonce: {nonce.hex()}, Ciphertext length: {len(ciphertext)}, Tag: {tag.hex()}")
            try:
                decrypted_data = decrypt_data(nonce, ciphertext, tag, key)
                self.history = decrypted_data.decode().split('\n')
                self.hashes = [generate_hash(entry) for entry in self.history]
                print("History loaded successfully.")
            except Exception as e:
                print(f"")
        except FileNotFoundError:
            print("Encrypted history file not found.")
        except Exception as e:
            print(f"Error loading history: {e}")

    def stop(self):
        self.running = False
        self.thread.join()
        self.save_history()


    def decrypt_entry(self, entry, password):
        try:
            key = derive_key(password)
            nonce, ciphertext, tag = encrypt_data(entry, key)
            return decrypt_data(nonce, ciphertext, tag, key)
        except Exception as e:
            print(f"Error decrypting entry: {e}")
            return None

    def verify_current_signature(self):
        try:
            with open(f'{self.user_dir}/clipboard_history.enc', 'rb') as f:
                encrypted_data = f.read()
            with open(f'{self.user_dir}/clipboard_history.sig', 'rb') as f:
                signature = f.read()
            return verify_signature(encrypted_data, signature, self.public_key)
        except FileNotFoundError:
            print("Clipboard history or signature file not found.")
            return False
        except Exception as e:
            print(f"Error verifying signature: {e}")
            return False
        
    def verify_entry(self, entry):
        entry_hash = generate_hash(entry)
        return entry_hash in self.hashes

    def clear_history(self):
        with self.lock:
            self.history = []
            self.hashes = []
            history_path = f'{self.user_dir}/clipboard_history.enc'
            signature_path = f'{self.user_dir}/clipboard_history.sig'
            hashes_path = f'{self.user_dir}/clipboard_hashes.txt'
            for path in [history_path, signature_path, hashes_path]:
                if os.path.exists(path):
                    os.remove(path)
            print("Clipboard history cleared.")

    def verify_entry_hash(self, entry_hash):
        """
        Verifica se um determinado hash de entrada está presente no último arquivo do histórico cifrado.
        
        Args:
            entry_hash (str): O hash da entrada a ser verificada.
        
        Returns:
            bool: True se o hash da entrada estiver presente, False caso contrário.
        """
        if entry_hash in self.hashes:
            return True
        else:
            return False

