import logging

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient

from consts import *
from src.dbutil import create_user, user_exists, update_balance, transfer, get_user_info

logging.basicConfig(level=logging.DEBUG)
app = FastAPI()


class RegisterForm(BaseModel):
    id: str
    name: str
    pubkey: str
    signature: str
    timestamp: int


class UpdateBalanceForm(BaseModel):
    id: str
    delta: str


class Order(BaseModel):
    from_id: str
    to_id: str
    amount: str
    comment: str


class OrderForm(BaseModel):
    order: Order
    signature: str
    cert: str


@app.post('/register')
async def register(form: RegisterForm):
    result, msg = await create_user(db, form.id, form.name, form.pubkey, form.signature, form.timestamp)
    if not result:
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': msg
        })
    return {
        'success': True,
        'cert': msg
    }


@app.post('/balance/update')
async def balance_update(form: UpdateBalanceForm):
    try:
        money_delta = Decimal(form.delta)
    except InvalidOperation:
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '金额非法'
        })

    if not user_exists(db, form.id):
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '账户不存在'
        })

    errmsg = await update_balance(db, form.id, money_delta)

    if errmsg is not None and errmsg != '':
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': errmsg
        })
    return {
        'success': True,
        'message': '存/取款成功'
    }


@app.get('/balance')
async def balance_get(id: str):
    if not user_exists(db, id):
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '账户不存在'
        })

    info = get_user_info(db, id)

    return {
        'success': True,
        'balance': info[DB_USER_BALANCE]
    }


@app.post('/order')
async def order(form: OrderForm):
    try:
        if (amount := Decimal(form.amount)) <= 0:
            raise HTTPException(status_code=400, detail={
                'success': False,
                'message': '金额必须大于0'
            })
    except InvalidOperation:
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '金额非法'
        })

    if not user_exists(db, form.from_id) or not user_exists(db, form.to_id):
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '账户不存在'
        })
    if form.from_id == form.to_id:
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': '不能给自己转账'
        })

    errmsg = await transfer(db, form.from_id, form.to_id, amount, form.signature, form.cert, form.comment)

    if errmsg is not None and errmsg != '':
        raise HTTPException(status_code=400, detail={
            'success': False,
            'message': errmsg
        })

    return {
        'success': True,
        'message': '转账成功'
    }


config = dict()
db = None
client = None
if __name__ == "__main__":
    mongo_url = f'mongodb://{DB_HOST}:{DB_PORT}/'
    print(f'Connecting database {mongo_url}...')
    client = MongoClient(mongo_url)
    print('Databases:')
    for __db in client.list_databases():
        print(__db)

    db = client[DB_NAME]

    uvicorn.run(app, host="0.0.0.0", port=LISTEN_PORT)
