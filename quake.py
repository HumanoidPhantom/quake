import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from blockchain import Blockchain
from uuid import uuid4
import hashlib
import base64
import json
from operator import itemgetter
import threading
import atexit
import main
import help

import requests
from flask import Flask, jsonify, request


class Quake:
    BASKET_SEND_TIME = 10  # sec
    BASKET_SIZE = 5  # txs
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
        self.signer = PKCS1_PSS.new(self.key)

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
            try:
                response = requests.get('https://%s%s/chain' % (self.host, self.port))
            except ConnectionError as msg:
                help.print_log(msg)
            else:
                if response.status_code == 200:
                    self.blockchain.chain = response.json()

    def generate_tx_hash(self, new_tx):
        h = SHA.new()

        h.update(('%s%s%s%s' % (new_tx['sender'], new_tx['receiver'], new_tx['amount'], new_tx['sequence']))
                 .encode())
        return h

    # def check_hash(self, pubkey, node):
    #     # fix
    #     node_hash = self.generate_node_hash(pubkey)
    #
    #     return node_hash == node

    def check_tx_basket(self, by_timer=True):
        help.print_log(('basket', len(self.tx_basket), 'valid', len(self.valid_tx), 'failed', len(self.failed_tx),
                        'nbrs', len(main.dic_neighbours), 'nodes', len(main.dic_network_node)))
        if not by_timer and len(self.tx_basket) < Quake.BASKET_SIZE:
            help.print_log("small basket")
            return

        self.send_basket_timer.cancel()
        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket)
        self.send_basket_timer.daemon = True
        self.send_basket_timer.start()

        threading.Thread(target=send_tx_basket, args=(main.dic_neighbours, self.tx_basket, self.hash)).start()

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey.encode())
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(tx_hash, base64.b64decode(signature.encode()))

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

    def check_tx(self, new_tx, node_hash=''):
        response = False

        if 'signatures' not in new_tx:
            new_tx['signatures'] = []

        if 'cur_signature' in new_tx and node_hash:
            new_tx['signatures'].append({
                'node': node_hash,
                'signature': new_tx['cur_signature']
            })

        if self.check_signatures(new_tx):
            # some additional verifications
            response = True

        response = response if self.valid_node else not response

        return response, new_tx

    def add_to_tx_list(self, new_tx, from_client=False):
        tx_hash = self.generate_tx_hash(new_tx)
        new_tx['hash'] = tx_hash.hexdigest()
        signature = self.signer.sign(tx_hash)
        is_new = True
        if tx_hash in self.valid_tx:
            is_new = False
            new_tx['signatures'] += \
                [item for item in self.valid_tx[tx_hash]['signatures'] if item not in new_tx['signatures']]

        new_tx['cur_signature'] = base64.b64encode(signature).decode()

        if len(new_tx['signatures']) / len(main.dic_network_node) > 2/3:
            self.voted_tx.append(tx_hash)

        self.valid_tx[new_tx['hash']] = new_tx

        if from_client:
            tx_index = self.find_tx(new_tx['hash'])
            if tx_index == -1:
                self.tx_basket.append(new_tx)

        return is_new, new_tx

    def add_to_failed_list(self, new_tx):
        new_tx['attempt'] = 0
        self.failed_tx.append(new_tx)

    def handle_tx_basket(self, tx_basket):
        updated_tx_basket_new = []
        updated_tx_basket_seen = []
        for new_tx in tx_basket['txs']:
            checked_tx = quake.check_tx(new_tx, tx_basket['node'])
            if checked_tx[0]:
                is_new, tmp_tx = quake.add_to_tx_list(checked_tx[1])
                if is_new:
                    updated_tx_basket_seen.append(tmp_tx)
                else:
                    updated_tx_basket_new.append(tmp_tx)
            else:
                quake.add_to_failed_list(checked_tx[1])

        if updated_tx_basket_new:
            send_tx_basket(main.dic_neighbours, updated_tx_basket_new, self.hash)

        if updated_tx_basket_seen:
            send_tx_basket(main.dic_neighbours, updated_tx_basket_new, self.hash, exclude_neigbors=(tx_basket['node']))

    def request_tx_by_hash(self, tx_hash):
        for nbr in main.dic_neighbours:
            try:
                response = requests.get('http://%s:%s/tx/info' % (nbr[1], peer_port(nbr[2])), params={'hash': tx_hash})
            except ConnectionError as msg:
                help.print_log(msg)
            else:
                if response.status_code != 200:
                    continue

                return json.loads(response.text)
        return {}


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


def peer_port(c_port):
    return int(c_port) - Quake.PORT_DISTANCE


def check_required(required, received):
    if not all(k in received for k in required):
        return 'Missing values', 400
    return -1


def send_tx_basket(neighbors, basket, node_hash, exclude_neigbors=()):
    txs_data = {
        'node': node_hash,
        'txs': basket,
    }

    is_sent = False
    help.print_log('here')
    for node_hash in neighbors:
        if node_hash in exclude_neigbors:
            continue

        try:
            response = requests.post('http://%s:%s/txs/basket' % (neighbors[node_hash][1],
                                                                  peer_port(neighbors[node_hash][2])), data=txs_data)
        except ConnectionError as msg:
            help.print_log(msg)
        else:
            if response.status_code == 200:
                is_sent = True

                txs = json.loads(response.text)
                help.print_log(txs)
                for new_tx in txs['txs']:
                    checked_tx = quake.check_tx(new_tx, node_hash)
                    if checked_tx[0]:
                        quake.add_to_tx_list(checked_tx[1])
                    else:
                        quake.add_to_failed_list(checked_tx[1])

    if is_sent:
        quake.tx_basket = []


@app.route('/chain', methods=['GET'])
def chain():
    # Get the list of peers
    response = quake.blockchain.chain

    return jsonify(response), 200


@app.route('/tx', methods=['POST'])
def tx():
    # Tx from client
    values = request.form
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
        quake.add_to_tx_list(checked_tx[1], from_client=True)
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
    values = request.form
    help.print_log(values)
    required = ['node']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    response = {
        'node': quake.hash,
        'txs': list(quake.valid_tx.values()),
    }

    if 'txs' in values:
        threading.Thread(target=quake.handle_tx_basket, args=(values, ))

    return jsonify(response), 200


@app.route('/tx/info', methods=['GET'])
def tx_info():
    values = request.args

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
    parser.add_argument('-p', '--port', default=49001, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    parser.add_argument('-n', '--neighbors', default=4, type=int, help='set the number of neighbors')

    parser.add_argument('-q', '--quite', help='run in quite mode')
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
    help.debug = not args.quite

    quake.host = connect_host
    quake.port = connect_port

    quake.update_chain()

    app.run(host=host, port=port)


if __name__ == '__main__':
    start()
