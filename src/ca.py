import base64
import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Certificate

from consts import *


def load_ECDSA_pubkey(pubkey: str) -> ec.EllipticCurvePublicKey:
    user_pubkey = serialization.load_pem_public_key(pubkey.encode())
    if not isinstance(user_pubkey, ec.EllipticCurvePublicKey):
        raise ValueError("pubkey should be ECDSA.")
    return user_pubkey


def register_request_cert(uid: str, pubkey: str, signature: str, timestamp: int) -> (bool, str):
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


def get_pubkey_by_uid(uid: str) -> (bool, str):
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


def verify_signature_with_cert(msg: str | bytes, signature: str | bytes, cert: Certificate) -> bool:
    return verify_signature_with_pubkey(msg, signature, cert.public_key())


def verify_signature_with_pubkey(msg: str | bytes, signature: str | bytes, pubkey: ec.EllipticCurvePublicKey) -> bool:
    if isinstance(msg, str):
        msg = msg.encode()
    try:
        pubkey.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


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
