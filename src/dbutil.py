import asyncio
from pymongo.database import Database

from consts import *
from src import ca

lock = asyncio.Lock()


async def create_user(db: Database, id: str, name: str, pubkey: str, signature: str, timestamp: int) -> (bool, str):
    """
    :return: (True, cert) if success, (False, errmsg) if failed
    """
    users = db[DB_COLL_USERS]

    async with lock:
        if user_exists(db, id):
            return False, '用户已存在'

        result, msg = ca.register_request_cert(CA_UID_PREFIX + id, pubkey, signature, timestamp)
        if not result:
            return False, msg

        users.insert_one({
            DB_USER_ID: id,
            DB_USER_NAME: name,
            DB_USER_BALANCE: str(INITIAL_CARD_BALANCE)
        })

        return True, msg


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


async def transfer(db: Database, id_payer: str, id_receiver: str, amount: Decimal, signature: str, cert: str,
                   comment: str) -> str | None:
    payer_balance = Decimal(get_user_info(db, id_payer).get(DB_USER_BALANCE))
    async with lock:
        if payer_balance < amount:
            return '付款人余额不足'

        _do_update_balance(db, id_payer, -amount)
        _do_update_balance(db, id_receiver, amount)
