import base64
import json
import time
from functools import wraps
from base64 import b64decode, b64encode

import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes

from consts import *

PEM_PRIVKEY_HEADER = "-----BEGIN PRIVATE KEY-----"
PEM_PRIVKEY_FOOTER = "-----END PRIVATE KEY-----"

def xor_ECDSA_privkey(privkey: str, passwd: str) -> str:
    st = privkey.find(PEM_PRIVKEY_HEADER) + len(PEM_PRIVKEY_HEADER)
    ed = privkey.find(PEM_PRIVKEY_FOOTER)
    encrypted = b64decode(privkey[st:ed])
    xor_key = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = len(encrypted),
        salt = b"\x8doSl\x13h\x15B2\x16\x8d.\xac-O\x96",
        iterations = 1926,
    ).derive(passwd.encode())
    decrypted = b64encode(bytes(a ^ b for (a, b) in zip(encrypted, xor_key))).decode()
    decrypted = '\n'.join(decrypted[i:i+64] for i in range(0, len(decrypted), 64))
    return f"{PEM_PRIVKEY_HEADER}\n{decrypted}\n{PEM_PRIVKEY_FOOTER}"


def load_ECDSA_privkey(privkey: str) -> ec.EllipticCurvePrivateKey:
    user_privkey = serialization.load_pem_private_key(privkey.encode(), None)
    if not isinstance(user_privkey, ec.EllipticCurvePrivateKey):
        raise ValueError("privkey should be ECDSA.")
    return user_privkey


def load_ECDSA_pubkey(pubkey: str) -> ec.EllipticCurvePublicKey:
    user_pubkey = serialization.load_pem_public_key(pubkey.encode())
    if not isinstance(user_pubkey, ec.EllipticCurvePublicKey):
        raise ValueError("pubkey should be ECDSA.")
    return user_pubkey


def register_request_cert(uid: str, pubkey: str, signature: str, timestamp: int) -> tuple[bool, str]:
    """
    :return: (True, cert) if success, (False, errmsg) if failed
    """
    r = requests.post(f"{CA_URL}/user?uid={uid}",
                      json={"sig": {"sig": signature, "timestamp": timestamp}, "pubkey": pubkey})
    print(r.request.url, r.request.body)
    resp = r.json()['data']
    if resp["result"] != 0:
        return False, resp["msg"]
    else:
        return True, resp['cert']


def get_pubkey_by_uid(uid: str) -> tuple[bool, str]:
    """
    :return: (True, pubkey) if success, (False, errmsg) if failed
    """
    r = requests.get(f"{CA_URL}/user?uid={uid}")
    resp = r.json()['data']
    if resp["result"] != 0:
        return False, resp["msg"]
    else:
        return True, resp['users'][0]['pubkey']


ca_pubkey = load_ECDSA_pubkey(open(CA_PUBKEY, 'r').read())
bank_privkey = load_ECDSA_privkey(
    xor_ECDSA_privkey(open(BANK_PRIVKEY, 'r').read(), BANK_PRIVKEY_PASSWORD))


def verify_signature_with_pubkey(msg: str | bytes, signature: bytes, pubkey: ec.EllipticCurvePublicKey) -> bool:
    if isinstance(msg, str):
        msg = msg.encode()
    try:
        pubkey.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def ieee_p1363_to_der(sig: bytes) -> bytes:
    return encode_dss_signature(
        int.from_bytes(sig[:32], "big"),
        int.from_bytes(sig[32:], "big"),
    )


def verify_ieee_p1363_signature(msg: str | bytes, signature: bytes, pubkey: ec.EllipticCurvePublicKey) -> bool:
    return verify_signature_with_pubkey(msg, ieee_p1363_to_der(signature), pubkey)


def load_cert(cert: str) -> tuple[ec.EllipticCurvePublicKey | None, str]:
    """
    :return: (pubkey, common_name) if success, (None, errmsg) if failed
    """
    c = x509.load_pem_x509_certificate(cert.encode())
    # first verify whether it is sign by CA
    if not verify_signature_with_pubkey(c.tbs_certificate_bytes, c.signature, ca_pubkey):
        return None, "证书签名无效"

    # then check revoke list
    r = requests.get(
        f"{CA_URL}/revoke/check",
        params={"digest": c.fingerprint(hashes.SHA256()).hex()}
    )
    resp = r.json()['data']
    if resp["result"] == 0:
        return None, "证书已被吊销"

    common_name = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if isinstance(common_name, bytes):
        common_name = common_name.decode()
    pubkey = c.public_key()
    return pubkey, common_name


def sign_with_bank(data):
    data["timestamp"] = int(time.time() * 1000)
    raw = json.dumps(data, sort_keys=True).encode()
    return {
        "data": data,
        "sig": base64.b64encode(bank_privkey.sign(raw, ec.ECDSA(hashes.SHA256()))).decode()
    }
