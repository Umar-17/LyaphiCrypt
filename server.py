# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

BINARY = "cipher.exe" if os.name == "nt" else "./cipher"

MAX_CHARS = 10000

@app.route('/encrypt', methods=['POST'])
def api_encrypt():
    data = request.get_json() or {}
    key  = data.get('key', '').strip()
    text = data.get('text', '')

    if not key or text is None:
        return jsonify({"error": "Missing key or text"}), 400

    if len(text) > MAX_CHARS:
        return jsonify({"error": f"Input too long. Maximum is {MAX_CHARS} characters (got {len(text)})."}), 400

    try:
        cmd = [BINARY, "--mode", "E", "--key", key, "--stdin"]
        print("Running:", " ".join(cmd))
        proc = subprocess.run(cmd, input=text, capture_output=True, text=True)

        if proc.returncode != 0:
            print("Cipher failed:", proc.stderr.strip())
            return jsonify({"error": "Encryption failed internally"}), 500

        out = proc.stdout.strip().splitlines()
        if len(out) < 2:
            return jsonify({"error": "Invalid cipher output"}), 500

        iv         = out[0].strip()
        cipher_str = out[1].strip()
        return jsonify({"iv": iv, "cipher": cipher_str})

    except Exception as e:
        print("Exception:", e)
        return jsonify({"error": str(e)}), 500


@app.route('/decrypt', methods=['POST'])
def api_decrypt():
    data   = request.get_json() or {}
    key    = data.get('key', '').strip()
    iv     = data.get('iv', '').strip()
    cipher = data.get('cipher', '').strip()

    if not key or not iv or not cipher:
        return jsonify({"error": "Missing key, iv or cipher"}), 400

    try:
        cmd = [BINARY, "--mode", "D", "--key", key, "--iv", iv, "--stdin"]
        print("Running:", " ".join(cmd))
        proc = subprocess.run(cmd, input=cipher, capture_output=True, text=True)

        if proc.returncode != 0:
            print("Decryption failed:", proc.stderr.strip())
            return jsonify({"error": "Decryption failed (wrong key or corrupted data)"}), 400

        plaintext = proc.stdout.strip()
        return jsonify({"plaintext": plaintext})

    except Exception as e:
        print("Exception:", e)
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
