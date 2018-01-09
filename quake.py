import sys
from Crypto.PublicKey import RSA
from blockchain import Blockchain
from uuid import uuid4
import hashlib
import json
from operator import itemgetter
import threading
import atexit
import main

import requests
from flask import Flask, jsonify, request


class Quake:
    BASKET_SEND_TIME = 20  # sec
    BASKET_SIZE = 20  # txs
    MAX_FAILED_TX_ATTEMPTS = 3
    PORT_DISTANCE = 1000

    def __init__(self, neighbors=4):
        self.valid_node = True

        self.host = ''
        self.__port = ''
        self.hash = main.publicKey
        self.neighbors = neighbors
        self.blockchain = Blockchain()

        self.key = main.privateKey

        # nodes list in main.dic_network_node
        # dict. change in code where list is assumed
        # self.nodes = [self.identity]

        # neighbors in main.dic_neighbours
        # dict. change in code, where list is assumed
        # self.neighbors_list = []

        self.tx_basket = []
        self.failed_tx = []
        self.valid_tx = {}

        self.voted_tx = []

        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket)
        self.send_basket_timer.daemon = True
        self.send_basket_timer.start()

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, c_port):
        self.__port = ':%i' % c_port if c_port else ''

    def update_chain(self):
        # TODO verify that chain is correct if node is not new
        if self.host:
            response = requests.get('https://%s%s/chain' % (self.host, self.port))
            if response.status_code == 200:
                self.blockchain.chain = response.json()

    def generate_node_hash(self, pubkey):
        return hashlib.sha1(('%s' % (pubkey, )).encode()).hexdigest()

    def generate_tx_hash(self, new_tx):
        return hashlib.sha1(
            ('%s%s%s%s' % (new_tx['sender'], new_tx['receiver'], new_tx['amount'], new_tx['sequence']))).hexdigest()

    # def check_hash(self, pubkey, node):
    #     # fix
    #     node_hash = self.generate_node_hash(pubkey)
    #
    #     return node_hash == node

    def check_tx_basket(self, by_timer=True):
        if not by_timer and len(self.tx_basket) < Quake.BASKET_SIZE:
            return

        self.send_basket_timer.cancel()
        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket)
        self.send_basket_timer.daemon = True
        self.send_basket_timer.start()

        threading.Thread(target=send_tx_basket, args=(main.dic_neighbours, self.tx_basket, self.hash))

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey)
        return key.verify(tx_hash, signature)

    def find_tx(self, tx_hash):
        txs = [index for index in range(len(self.tx_basket)) if self.tx_basket[index]['hash'] == tx_hash]

        if len(txs):
            return txs[0]

        return -1

    def check_signatures(self, new_tx):
        tx_hash = self.generate_tx_hash(new_tx)
        result = True
        for item in new_tx['signatures']:
            if not item['node'] in main.dic_network_node:
                continue
            node = main.dic_network_node[item['node']]
            result &= self.verify_signature(node[0], item['signature'], tx_hash)

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

        response = response if self.valid_node else not response

        return response, new_tx

    def add_to_tx_list(self, new_tx, from_client=False):
        tx_hash = self.generate_tx_hash(new_tx)
        new_tx['hash'] = tx_hash
        signature = self.key.sign(tx_hash)
        is_new = True
        if tx_hash in self.valid_tx:
            is_new = False
            new_tx['signatures'] += \
                [item for item in self.valid_tx[tx_hash]['signatures'] if item not in new_tx['signatures']]

        new_tx['cur_signature'] = signature

        if len(new_tx['signatures']) / len(main.dic_network_node) > 2/3:
            self.voted_tx.append(tx_hash)

        self.valid_tx[tx_hash] = new_tx

        if from_client:
            tx_index = self.find_tx(tx_hash)
            if tx_index == -1:
                self.tx_basket.append(tx)

        return is_new, new_tx

    def add_to_failed_list(self, new_tx):
        new_tx['attempt'] = 0
        self.failed_tx.append(new_tx)

    def handle_tx_basket(self, tx_basket):
        updated_tx_basket_new = []
        updated_tx_basket_seen = []
        for new_tx in tx_basket['txs']:
            checked_tx = quake.check_tx(new_tx)
            if checked_tx[0]:
                is_new, tmp_tx = quake.add_to_tx_list(checked_tx[1])
                if is_new:
                    updated_tx_basket_seen.append(tmp_tx)
                else:
                    updated_tx_basket_new.append(tmp_tx)
            else:
                quake.add_to_failed_list(checked_tx[1])

        if updated_tx_basket_new:
            send_tx_basket(self.hash, updated_tx_basket_new, main.dic_neighbours)

        if updated_tx_basket_seen:
            neighbors = [item for item in main.dic_neighbours if item != tx_basket['node']]
            send_tx_basket(self.hash, updated_tx_basket_new, neighbors)

    def request_tx_by_hash(self, tx_hash):
        for nbr in main.dic_neighbours:
            response = requests.get('http://%s:%s/tx/info' % (nbr[1], peer_port(nbr[2])), params={'hash': tx_hash})
            if response.status_code != 200:
                continue

            return json.loads(response.text)
        return {}


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


def peer_port(c_port):
    return int(c_port) + Quake.PORT_DISTANCE


def check_required(required, received):
    if not all(k in received for k in required):
        return 'Missing values', 400
    return -1


def send_tx_basket(node_hash, basket, neighbors):
    txs_data = {
        'node': node_hash,
        'txs': basket,
    }

    for node in neighbors:
        response = requests.post('http://%s:%s/txs/basket' % (node[1], peer_port(node[2])), data=txs_data)

        if response.status_code == 200:
            txs = json.loads(response.text)
            for new_tx in txs:
                checked_tx = quake.check_tx(new_tx)
                if checked_tx[0]:
                    quake.add_to_tx_list(checked_tx[1])
                else:
                    quake.add_to_failed_list(checked_tx[1])


@app.route('/chain', methods=['GET'])
def chain():
    # Get the list of peers
    response = quake.blockchain.chain

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

    checked_tx = quake.check_tx(new_tx)
    if checked_tx[0]:
        quake.add_to_tx_list(checked_tx[1])
        quake.check_tx_basket(by_timer=False)
    else:
        quake.add_to_failed_list(checked_tx[1])

    return 'OK', 200


# @app.route('/neighbor', methods=['POST'])
# def neighbor():
#     # Receive node's identity. Become a neighbor
#     values = request.get_json()
#     required = ['hash', 'pubkey', 'host', 'port']
#
#     check_result = check_required(required, values)
#     if check_result != -1:
#         return check_result
#
#     response = {}
#     return jsonify(response), 200


@app.route('/txs/basket', methods=['POST'])
def txs_basket():
    values = request.get_json()

    required = ['node', 'txs']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    response = {
        'node': quake.hash,
        'txs': quake.valid_tx.values(),
    }

    threading.Thread(target=quake.handle_tx_basket, args=(values, ))

    return jsonify(response), 200


@app.route('/tx/info')
def tx_info():
    values = request.get_json()

    required = ['hash']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    if values['hash'] in quake.voted_tx:
        response = quake.voted_tx[values['hash']]
        return jsonify(response), 200

    return 'Not found', 404


def start():
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip or url')
    parser.add_argument('-p', '--socket_port', default=49001, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    parser.add_argument('-n', '--neighbors', default=4, type=int, help='set the number of neighbors')

    parser.add_argument('-nv', '--non_valid_node', help="Emulate non-valid node", action="store_true")

    args = parser.parse_args()
    connect_host = args.connect_to_host
    connect_port = args.connect_to_port

    host = args.host
    port = args.port
    main.port = str(args.port + Quake.PORT_DISTANCE)

    main.run()

    quake.neighbors = args.neighbors

    quake.valid_node = not args.non_valid_node

    quake.host = connect_host
    quake.port = connect_port

    quake.update_chain()

    app.run(host=host, port=port)


if __name__ == '__main__':
    start()
