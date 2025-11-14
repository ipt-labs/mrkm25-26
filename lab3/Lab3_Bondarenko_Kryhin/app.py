"""Simple ECDSA Web API"""

import io
import zipfile

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)


@app.route("/generate_keys", methods=["GET"])
def generate_keys():
    """
    Generates a new ECC (ECDSA) key pair and returns them
    as a downloadable zip file containing two .pem files.
    """
    key = ECC.generate(curve="P-256")

    private_key_pem = key.export_key(format="PEM")
    public_key_pem = key.public_key().export_key(format="PEM")

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("privkey.pem", private_key_pem)
        zf.writestr("pubkey.pem", public_key_pem)
    memory_file.seek(0)

    return send_file(
        memory_file,
        download_name="keys.zip",
        mimetype="application/zip",
        as_attachment=True,
    )


@app.route("/sign", methods=["POST"])
def sign_message():
    """
    Signs an uploaded message file using an uploaded private key file.
    Returns the binary signature as a downloadable file.
    Expects multipart/form-data:
    - 'privkey': The private key .pem file
    - 'message': The file to sign
    """
    try:
        if "privkey" not in request.files:
            return jsonify({"error": "Missing 'privkey' file part"}), 400
        if "message" not in request.files:
            return jsonify({"error": "Missing 'message' file part"}), 400

        privkey_file = request.files["privkey"]
        message_file = request.files["message"]

        private_key_pem = privkey_file.read()
        message = message_file.read()

        key = ECC.import_key(private_key_pem)
        h = SHA256.new(message)
        signer = DSS.new(key, "fips-186-3")
        signature = signer.sign(h)

        signature_file_obj = io.BytesIO(signature)
        signature_file_obj.seek(0)

        return send_file(
            signature_file_obj,
            download_name="signature.bin",
            mimetype="application/octet-stream",
            as_attachment=True,
        )

    except (ValueError, TypeError, ImportError) as e:
        return jsonify({"error": f"Invalid key or data: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/verify", methods=["POST"])
def verify_signature():
    """
    Verifies a signature file against a message file and a public key file.
    Expects multipart/form-data:
    - 'pubkey': The public key .pem file
    - 'message': The original message file
    - 'signature': The binary signature file (e.g., 'signature.bin')
    """
    try:
        if "pubkey" not in request.files:
            return jsonify({"error": "Missing 'pubkey' file part"}), 400
        if "message" not in request.files:
            return jsonify({"error": "Missing 'message' file part"}), 400
        if "signature" not in request.files:
            return jsonify({"error": "Missing 'signature' file part"}), 400

        pubkey_file = request.files["pubkey"]
        message_file = request.files["message"]
        signature_file = request.files["signature"]

        public_key_pem = pubkey_file.read()
        message = message_file.read()
        signature = signature_file.read()

        key = ECC.import_key(public_key_pem)
        h = SHA256.new(message)
        verifier = DSS.new(key, "fips-186-3")

        verifier.verify(h, signature)

        return jsonify({"verified": True})

    except (ValueError, TypeError):
        return jsonify({"verified": False, "error": "Invalid signature"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=False, port=5000, host="127.0.0.1")
