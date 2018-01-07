import sys
from Crypto.PublicKey import RSA
from blockchain import Blockchain
from uuid import uuid4
import hashlib
import json
from operator import itemgetter
import threading
import atexit

import requests
from flask import Flask, jsonify, request


class Quake:
    BASKET_SEND_TIME = 20  # sec
    BASKET_SIZE = 20  # txs
    MAX_FAILED_TX_ATTEMPTS = 3

    def __init__(self, neighbors=4):
        self.valid_node = True

        self.host = ''
        self.__port = ''
        self.neighbors = neighbors
        self.blockchain = Blockchain()

        self.key = RSA.generate(2048)

        self.identity = self.generate_identity()
        self.nodes = [self.identity]

        self.neighbors_list = []

        self.update_data()

        self.tx_basket = []
        self.failed_tx = []
        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket).start()

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, c_port):
        self.__port = ':%i' % c_port if c_port else ''

    def update_data(self):
        if self.host:
            response = requests.get('https://%s%s/data' % (self.host, self.port))
            if response.status_code == 200:
                self.nodes = response.json()['nodes']
                self.blockchain.chain = response.json()['chain']

    def generate_node_hash(self, pubkey, node_host, node_port):
        return hashlib.sha256(('%s%s%s' % (pubkey, node_host, node_port)).encode())

    def generate_tx_hash(self, new_tx):
        return hashlib.sha256(('%s%s%s%s' % (new_tx['sender'], new_tx['receiver'], new_tx['amount'], new_tx['sequence'])))

    def generate_identity(self):
        pubkey = self.key.publickey().exportKey()
        node_hash = self.generate_node_hash(pubkey, self.host, self.port)
        return {
            'hash': node_hash,
            'pubkey': pubkey,
            'address': self.host + self.port
        }

    def sort_nodes(self):
        self.nodes = sorted(self.nodes, key=itemgetter('hash'))

    def check_hash(self, identity):
        node_hash = self.generate_node_hash(identity['pubkey'], identity['node_host'], identity['node_port'])

        return node_hash == identity['hash']

    def check_tx_basket(self):
        if len(self.tx_basket) >= Quake.BASKET_SIZE:
            self.send_tx_basket()

    def send_tx_basket(self):
        self.send_basket_timer.cancel()
        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket)
        self.send_basket_timer.start()

        txs_data = {
            'node': self.identity['hash'],
            'txs': self.tx_basket,
        }

        for node in self.neighbors_list:
            requests.post('http://%s/txs/basket' % node['address'], data=txs_data)

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey)
        return key.verify(tx_hash, signature)

    def find_node(self, hash):
        nodes = [item for item in self.nodes if item['hash'] == hash]
        if len(nodes):
            return nodes[0]

        return None

    def check_signatures(self, new_tx):
        tx_hash = self.generate_tx_hash(new_tx)
        result = True
        for item in new_tx['signatures']:
            node = self.find_node(item['node'])
            if not node:
                continue

            result &= self.verify_signature(node['pubkey'], item['signature'], tx_hash)

        return result

    def check_tx(self, new_tx):
        response = False

        if 'signatures' not in new_tx:
            new_tx['signatures'] = []

        new_tx['signatures'].append({
            'node': new_tx['node'],
            'signature': new_tx['cur_signature']
        })

        if self.check_signatures(new_tx):
            # some additional verifications
            response = True

        return response if self.valid_node else not response

    def add_to_tx_basket(self, new_tx):
        tx_hash = self.generate_tx_hash(new_tx)
        signature = self.key.sign(tx_hash)

        new_tx['cur_signature'] = signature

        self.tx_basket.append(tx)

    def add_to_failed_list(self, new_tx):
        new_tx['attempt'] = 0
        self.failed_tx.append(new_tx)


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


def check_required(required, received):
    if not all(k in received for k in required):
        return 'Missing values', 400
    return -1


@app.route('/data', methods=['GET'])
def data():
    # Get the list of peers
    response = {'nodes': quake.nodes, 'chain': quake.blockchain.chain}

    return jsonify(response), 200


@app.route('/tx', methods=['POST'])
def tx():
    # Tx from client
    values = request.get_json()

    required = ['sender', 'receiver', 'amount', 'sequence']

    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    new_tx = {
        'sender': values['sender'],
        'receiver': values['receiver'],
        'amount': values['amount'],
        'sequence': values['sequence']
    }

    if quake.check_tx(new_tx):
        quake.add_to_tx_basket(new_tx)
        quake.check_tx_basket()
    else:
        quake.add_to_failed_list(new_tx)

    return 'OK', 200


@app.route('/neighbor', methods=['POST'])
def neighbor():
    # Receive node's identity. Become a neighbor
    values = request.get_json()
    required = ['hash', 'pubkey', 'host', 'port']

    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    response = {}
    return jsonify(response), 200


@app.route('/txs/basket', methods=['POST'])
def txs_basket():
    values = request.get_json()

    required = ['node', 'txs']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    for new_tx in values['txs']:
        if quake.check_tx(new_tx):
            quake.add_to_tx_basket(new_tx)
        else:
            quake.add_to_failed_list(new_tx)

    quake.check_tx_basket()

    return 'OK', 200


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip or url')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    parser.add_argument('-n', '--neighbors', default=4, type=int, help='set the number of neighbors')

    parser.add_argument('-nv', '--non_valid_node', help="Emulate non-valid node", action="store_true")

    args = parser.parse_args()
    connect_host = args.connect_to_host
    connect_port = args.connect_to_port

    host = args.host
    port = args.port

    quake.neighbors = args.neighbors

    quake.valid_node = not args.non_valid_node

    quake.nodes = connect_host
    quake.port = connect_port
    quake.update_data()

    app.run(host=host, port=port)


if __name__ == '__main__':
    main()
