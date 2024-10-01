import unittest
import time
import os
import pyperclip
from clipboard_manager import ClipboardManager
from encryption import generate_key, encrypt_data, decrypt_data, generate_hash
from signature import generate_rsa_keys, sign_data, verify_signature

class TestClipboardManager(unittest.TestCase):
    def setUp(self):
        self.cm = ClipboardManager()
        time.sleep(1)  # Wait for the clipboard manager to start

    def tearDown(self):
        self.cm.stop()
        if os.path.exists('clipboard_history.enc'):
            os.remove('clipboard_history.enc')
        if os.path.exists('clipboard_history.sig'):
            os.remove('clipboard_history.sig')
        if os.path.exists('clipboard_hashes.txt'):
            os.remove('clipboard_hashes.txt')

    def test_generate_key(self):
        key = generate_key()
        self.assertEqual(len(key), 32)

    def test_encrypt_decrypt(self):
        key = generate_key()
        data = "test data"
        nonce, ciphertext, tag = encrypt_data(data, key)
        decrypted_data = decrypt_data(nonce, ciphertext, tag, key)
        self.assertEqual(decrypted_data.decode(), data)

    def test_generate_hash(self):
        data = "test data"
        hash1 = generate_hash(data)
        hash2 = generate_hash(data)
        self.assertEqual(hash1, hash2)

    def test_generate_rsa_keys(self):
        private_key, public_key = generate_rsa_keys()
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

    def test_sign_verify(self):
        private_key, public_key = generate_rsa_keys()
        data = b"test data"
        signature = sign_data(data, private_key)
        is_verified = verify_signature(data, signature, public_key)
        self.assertTrue(is_verified)

    def test_clipboard_capture(self):
        pyperclip.copy("test entry 1")
        time.sleep(3)  # Wait for the clipboard manager to capture the entry
        self.assertIn("test entry 1", self.cm.history)

    def test_entry_verification(self):
        entry = "test entry 2"
        pyperclip.copy(entry)
        time.sleep(3)  # Wait for the clipboard manager to capture the entry
        self.assertTrue(self.cm.verify_entry(entry))

    def test_save_history(self):
        pyperclip.copy("test entry 3")
        time.sleep(3)  # Wait for the clipboard manager to capture the entry
        self.cm.save_history()
        with open('clipboard_history.enc', 'rb') as f:
            encrypted_data = f.read()
        self.assertGreater(len(encrypted_data), 0)

    def test_load_history(self):
        pyperclip.copy("test entry 4")
        time.sleep(3)  # Wait for the clipboard manager to capture the entry
        self.cm.save_history()
        self.cm.stop()
        self.cm = ClipboardManager()
        self.assertIn("test entry 4", self.cm.history)

if __name__ == "__main__":
    unittest.main()
