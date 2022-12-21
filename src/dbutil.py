import asyncio
import base64
from pymongo.database import Database

from consts import *
from src import ca

lock = asyncio.Lock()


async def create_user(db: Database, id: str, name: str, cert: str) -> str | None:
    """
    :return: 返回错误信息，为None则为成功
    """
    users = db[DB_COLL_USERS]

    async with lock:
        if user_exists(db, id):
            return '账户已存在'

        pubkey, common_name = ca.load_cert(cert)
        if pubkey is None:
            return '证书无效'

        if common_name != CA_UID_PREFIX + id:
            return '证书与卡号不匹配'

        users.insert_one({
            DB_USER_ID: id,
            DB_USER_NAME: name,
            DB_USER_BALANCE: str(INITIAL_CARD_BALANCE),
            DB_USER_CERT: cert
        })


def check_login(db: Database, id: str, signature: str, timestamp: int) -> str | None:
    """
    :return: 返回错误信息，为None则为成功
    """

    msg = f'{timestamp}||{CA_UID_PREFIX + id}||POST:/login'
    pubkey, common_name = ca.load_cert(get_user_info(db, id)[DB_USER_CERT])
    signature = base64.b64decode(signature)
    if not ca.verify_ieee_p1363_signature(msg, signature, pubkey):
        return '签名无效'


def user_exists(db: Database, id: str):
    return db[DB_COLL_USERS].count_documents({DB_USER_ID: id}, limit=1)


def get_user_info(db: Database, id: str):
    return db[DB_COLL_USERS].find_one({DB_USER_ID: id})


def _do_update_balance(db: Database, id: str, balance_delta: Decimal):
    """
    无锁，内部调用
    """
    info = get_user_info(db, id)

    info[DB_USER_BALANCE] = str(Decimal(info[DB_USER_BALANCE]) + balance_delta)

    db[DB_COLL_USERS].update_one({DB_USER_ID: id}, {'$set': {DB_USER_BALANCE: info[DB_USER_BALANCE]}})


async def update_balance(db: Database, id: str, balance_delta: Decimal) -> str | None:
    """
    :return: 返回错误信息，为None则为成功
    """

    info = get_user_info(db, id)

    if not info:
        return '账户不存在'
    async with lock:
        _do_update_balance(db, id, balance_delta)


async def transfer(db: Database, from_id: str, to_id: str, amount: str, comment: str, signature: str) -> str | None:
    msg = f'{from_id}||{to_id}||{amount}||{comment}'
    pubkey, common_name = ca.load_cert(get_user_info(db, from_id)[DB_USER_CERT])
    signature = base64.b64decode(signature)
    if not ca.verify_ieee_p1363_signature(msg, signature, pubkey):
        return '签名无效'

    amount = Decimal(amount)
    async with lock:
        payer_balance = Decimal(get_user_info(db, from_id).get(DB_USER_BALANCE))
        if payer_balance < amount:
            return '付款人余额不足'

        _do_update_balance(db, from_id, -amount)
        _do_update_balance(db, to_id, amount)
