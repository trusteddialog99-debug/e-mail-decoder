
import json
import base64
from flask import Flask, request, jsonify

app = Flask(__name__)

def decode_email(encoded_email):
    try:
        # Base64-Decodierung
        decoded_bytes = base64.b64decode(encoded_email)
        decoded_str = decoded_bytes.decode("utf-8")
        return decoded_str
    except Exception as e:
        return f"Fehler beim Dekodieren: {str(e)}"

@app.route("/decode", methods=["POST"])
def decode():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Bitte 'email' im JSON-Body angeben"}), 400

    encoded_email = data["email"]
    decoded_email = decode_email(encoded_email)
    return jsonify({"decoded_email": decoded_email})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
