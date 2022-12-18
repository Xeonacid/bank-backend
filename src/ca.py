import base64
import requests
from cryptography import x509
from cryptography.exceptions import InvalidSignature
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
    '''
    :return: (True, cert) if success, (False, errmsg) if failed
    '''
    r = requests.post(f"{CA_URL}/user?uid={uid}",
                      json={"sig": {"sig": signature, "timestamp": timestamp}, "pubkey": pubkey})
    resp = r.json()['data']
    if resp["result"] != 0:
        return False, resp["msg"]
    else:
        return True, resp['cert']


ca_pubkey = load_ECDSA_pubkey(open(CA_PUBKEY, 'r').read())


def verify_signature_with_cert(msg: str, signature: str, cert: Certificate) -> bool:
    pubkey = cert.public_key()
    try:
        pubkey.verify(base64.b64decode(signature), msg.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def owner_of_cert(cert: Certificate) -> str:
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
