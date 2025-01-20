from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import logging

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Simulated user database
users = {
    "user1": bcrypt.hashpw("password1".encode('utf-8'), bcrypt.gensalt())
}

# Generate a random AES key (must be 16, 24, or 32 bytes long)
aes_key = get_random_bytes(16)

# Helper function to log events
def log_event(event):
    logging.info(event)
    
# Serve the frontend files
@app.route('/<path:path>')
def serve_frontend(path):
    return send_from_directory('frontend', path)

@app.route('/')
def home():
    return send_from_directory('frontend', 'index.html')

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
        log_event(f"User {username} logged in successfully.")
        return jsonify({"message": "Login successful!"}), 200
    else:
        log_event(f"Failed login attempt for user {username}.")
        return jsonify({"message": "Invalid credentials!"}), 401

# Encrypt a message using AES
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV for decryption

# Decrypt a message using AES
def decrypt_message(ciphertext, key):
    iv = ciphertext[:AES.block_size]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

# Generate a SHA-256 hash for message integrity
def generate_hash(message):
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

# Endpoint to send an encrypted message
@app.route('/send', methods=['POST'])
def send_message():
    data = request.json
    message = data.get('message')
    encrypted_message = encrypt_message(message, aes_key)
    log_event(f"Message sent: {message}")
    return jsonify({"encrypted_message": encrypted_message.hex()}), 200

# Endpoint to receive and decrypt a message
@app.route('/receive', methods=['POST'])
def receive_message():
    data = request.json
    encrypted_message = bytes.fromhex(data.get('encrypted_message'))
    decrypted_message = decrypt_message(encrypted_message, aes_key)
    log_event(f"Message received and decrypted: {decrypted_message}")
    return jsonify({"decrypted_message": decrypted_message}), 200

# Endpoint to send a message with integrity check
@app.route('/send-with-hash', methods=['POST'])
def send_with_hash():
    data = request.json
    message = data.get('message')
    message_hash = generate_hash(message)
    encrypted_message = encrypt_message(message, aes_key)
    log_event(f"Message sent with hash: {message}")
    return jsonify({
        "encrypted_message": encrypted_message.hex(),
        "message_hash": message_hash
    }), 200

# Endpoint to receive and verify a message's integrity
@app.route('/receive-with-hash', methods=['POST'])
def receive_with_hash():
    data = request.json
    encrypted_message = bytes.fromhex(data.get('encrypted_message'))
    received_hash = data.get('message_hash')
    decrypted_message = decrypt_message(encrypted_message, aes_key)

    if generate_hash(decrypted_message) == received_hash:
        log_event(f"Message integrity verified: {decrypted_message}")
        return jsonify({"message": "Message integrity verified!", "decrypted_message": decrypted_message}), 200
    else:
        log_event(f"Message integrity check failed: {decrypted_message}")
        return jsonify({"message": "Message has been altered!"}), 400

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)