from flask import Flask, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import hmac
import hashlib
import threading
import time
import re

app = Flask(__name__)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# AES Encryption class
class AESEncryption:
    def __init__(self, key):
        self.key = key
        self.block_size = AES.block_size

    def update_key(self, new_key):
        self.key = new_key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(plaintext.encode(), self.block_size))
        return iv, ciphertext

    def decrypt(self, iv, ciphertext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), self.block_size)
        return decrypted.decode()

# Key Management class
class KeyManager:
    def __init__(self, key_length=32):
        self.key_length = key_length
        self.current_key = self.generate_key()

    def generate_key(self):
        return os.urandom(self.key_length)

    def get_current_key(self):
        return self.current_key

    def rotate_key(self):
        self.current_key = self.generate_key()
        return self.current_key

key_manager = KeyManager()
aes = AESEncryption(key_manager.get_current_key())

def key_rotation_schedule(interval=3600):
    while True:
        time.sleep(interval)
        new_key = key_manager.rotate_key()
        aes.update_key(new_key)
        print("Key rotated")

# Start key rotation in a separate thread
rotation_thread = threading.Thread(target=key_rotation_schedule, args=(3600,))
rotation_thread.daemon = True
rotation_thread.start()

def validate_input(data, required_fields):
    if not data:
        return False, "No data provided"
    for field in required_fields:
        if field not in data:
            return False, f"Missing field: {field}"
        if not isinstance(data[field], str):
            return False, f"Invalid data type for field: {field}"
        if not re.match(r'^[a-zA-Z0-9\s]+$', data[field]):
            return False, f"Invalid characters in field: {field}"
    return True, None

@app.route('/encrypt', methods=['POST'])
@limiter.limit("10 per minute")
def encrypt_message():
    data = request.json
    is_valid, error = validate_input(data, ['message'])
    if not is_valid:
        return jsonify({"error": error}), 400
    message = data['message']
    iv, encrypted_message = aes.encrypt(message)
    hmac_value = generate_hmac(key_manager.get_current_key(), message)
    return jsonify({
        "iv": iv.hex(),
        "encrypted_message": encrypted_message.hex(),
        "hmac": hmac_value
    })

@app.route('/decrypt', methods=['POST'])
@limiter.limit("10 per minute")
def decrypt_message():
    data = request.json
    is_valid, error = validate_input(data, ['iv', 'encrypted_message', 'hmac'])
    if not is_valid:
        return jsonify({"error": error}), 400
    iv = bytes.fromhex(data['iv'])
    encrypted_message = bytes.fromhex(data['encrypted_message'])
    hmac_value = data['hmac']
    decrypted_text = aes.decrypt(iv, encrypted_message)
    if verify_hmac(key_manager.get_current_key(), decrypted_text, hmac_value):
        return jsonify({"decrypted_message": decrypted_text})
    else:
        return jsonify({"error": "HMAC verification failed"}), 400

@app.route('/')
def serve_frontend():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static_file(path):
    return send_from_directory('static', path)

def generate_hmac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(key, message, hmac_to_verify):
    return hmac.compare_digest(generate_hmac(key, message), hmac_to_verify)

if __name__ == '__main__':
    app.run(debug=True)