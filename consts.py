from decimal import Decimal

LISTEN_PORT = 8000

DB_HOST = '127.0.0.1'
DB_PORT = 27017

CA_URL = 'http://127.0.0.1:8080'
CA_PUBKEY = 'assets/ca_pub.pem'

INITIAL_CARD_BALANCE = Decimal(0)  # Decimal('1145.14')

DB_NAME = 'bank'

DB_COLL_USERS = 'users'

DB_USER_ID = 'id'
DB_USER_NAME = 'name'
DB_USER_BALANCE = 'balance'

CA_UID_PREFIX = 'BANK_'
