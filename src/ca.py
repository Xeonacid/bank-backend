import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

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
    print(resp)
    if resp["result"] != 0:
        return False, resp["msg"]
    else:
        return True, resp['cert']
