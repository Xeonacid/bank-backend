from decimal import *

LISTEN_PORT = 8000

DB_HOST = '127.0.0.1'
DB_PORT = 27017

CA_URL = 'http://127.0.0.1:49156'
CA_PUBKEY = 'assets/ca_pub.pem'
BANK_PRIVKEY = 'assets/bank.pem'
BANK_PRIVKEY_PASSWORD = "BANK_PRIVKEY_PASSWORD"

INITIAL_CARD_BALANCE = Decimal(0)  # Decimal('1145.14')

DB_NAME = 'bank'

DB_COLL_USERS = 'users'

DB_USER_ID = 'id'
DB_USER_NAME = 'name'
DB_USER_BALANCE = 'balance'
DB_USER_CERT = 'cert'
DB_USER_LAST_ORDER_TIMESTAMP = 'last_order_timestamp'

CA_UID_PREFIX = 'BANK_'
