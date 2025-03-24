import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
from urllib.parse import urlparse, parse_qs
import base64
import sqlite3

# Database path
DB_PATH = 'totally_not_my_privateKeys.db'

# Create database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                (kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

# Create RSA key pair with a kid and expiry timestamp
def generate_key_pair(expiry=None):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    expiry = expiry or (int(time.time()) + 3600)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (private_pem, expiry))
    kid = c.lastrowid
    conn.commit()
    conn.close()

    key = {
        "kid": str(kid),
        "private_key": private_pem,
        "public_key": public_pem,
        "expiry": expiry,
        "public_numbers": public_key.public_numbers()
    }
    return key

# HTTP request handler
class JWKSServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/.well-known/jwks.json"):
            self.serve_jwks()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        if self.path.startswith("/auth"):
            self.serve_auth()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_PUT(self):
        self.method_not_allowed()

    def do_DELETE(self):
        self.method_not_allowed()

    def do_PATCH(self):
        self.method_not_allowed()

    def do_HEAD(self):
        self.method_not_allowed()

    def method_not_allowed(self):
        self.send_response(405)
        self.send_header("Allow", "GET, POST")
        self.end_headers()

    def serve_jwks(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (int(time.time()),))
        valid_keys = c.fetchall()
        conn.close()
        
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key[0]),
                    "alg": "RS256",
                    "n": base64.urlsafe_b64encode(
                        serialization.load_pem_private_key(key[1], password=None, backend=default_backend())
                        .public_key().public_numbers().n.to_bytes((serialization.load_pem_private_key(key[1], password=None, backend=default_backend()).key_size + 7) // 8, byteorder="big")
                    ).decode("utf-8").rstrip("="),
                    "e": base64.urlsafe_b64encode(
                        serialization.load_pem_private_key(key[1], password=None, backend=default_backend())
                        .public_key().public_numbers().e.to_bytes((serialization.load_pem_private_key(key[1], password=None, backend=default_backend()).key_size + 7) // 8, byteorder="big")
                    ).decode("utf-8").rstrip("="),
                }
                for key in valid_keys
            ]
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())

    def serve_auth(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        expired = query_params.get("expired", ["false"])[0].lower() == "true"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        if expired:
            c.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1", (int(time.time()),))
        else:
            c.execute("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (int(time.time()),))
        
        key = c.fetchone()
        conn.close()

        if not key:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"No valid keys available")
            return

        private_key = serialization.load_pem_private_key(key[1], password=None, backend=default_backend())
        
        payload = {
            "sub": "1234567890",
            "name": "Chris Redfield",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(key[0])})

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"token": token}).encode())

if __name__ == "__main__":
    init_db()
    generate_key_pair()  # Valid key
    generate_key_pair(expiry=int(time.time()) - 3600)  # Expired key
    server_address = ("", 8080)
    httpd = HTTPServer(server_address, JWKSServer)
    print("JWKS Server running on http://localhost:8080")
    httpd.serve_forever()