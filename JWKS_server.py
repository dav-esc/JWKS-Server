import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
from urllib.parse import urlparse, parse_qs
import base64

keys = []

#Create RSA key pair with a kid and expiry timestamp
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

    #Create a key object
    key_id = str(len(keys) + 1)
    expiry = expiry or (int(time.time()) + 3600)
    key = {
        "kid": key_id,
        "private_key": private_pem,
        "public_key": public_pem,
        "expiry": expiry,
        "public_numbers": public_key.public_numbers()
    }
    keys.append(key)
    return key

#Generate an initial valid key and an expired key
generate_key_pair()  # Valid key
generate_key_pair(expiry=int(time.time()) - 3600)  # Expired key

#HTTP request handler
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
        #Handle unsupported HTTP methods.
        self.send_response(405)
        self.send_header("Allow", "GET, POST")
        self.end_headers()

    def serve_jwks(self):
        # Filter out expired keys for JWKS response
        valid_keys = [key for key in keys if key["expiry"] > int(time.time())]
        
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": key["kid"],
                    "alg": "RS256",
                    "n": base64.urlsafe_b64encode(
                        key["public_numbers"].n.to_bytes((key["public_numbers"].n.bit_length() + 7) // 8, byteorder="big")
                    ).decode("utf-8").rstrip("="),
                    "e": base64.urlsafe_b64encode(
                        key["public_numbers"].e.to_bytes((key["public_numbers"].e.bit_length() + 7) // 8, byteorder="big")
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
        #parse query parameters
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        expired = query_params.get("expired", ["false"])[0].lower() == "true"

        #select key
        if expired:
            #expired key
            expired_keys = [key for key in keys if key["expiry"] <= int(time.time())]
            if not expired_keys:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No expired keys available")
                return
            key = expired_keys[0]
            exp_time = int(time.time()) - 3600 
        else:
            #use valid key
            valid_keys = [key for key in keys if key["expiry"] > int(time.time())]
            if not valid_keys:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No valid keys available")
                return
            key = valid_keys[0]
            exp_time = int(time.time()) + 3600
        #create the JWT
        payload = {
            "name": "Chris Redfield",
            "exp": exp_time,
        }
        
        token = jwt.encode(payload, key["private_key"], algorithm="RS256", headers={"kid": key["kid"]})

        #send reponse and token
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"token": token}).encode())

if __name__ == "__main__":
    server_address = ("", 8080)
    httpd = HTTPServer(server_address, JWKSServer)
    print("JWKS Server running on http://localhost:8080")
    httpd.serve_forever()
