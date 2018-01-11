import sys
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
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
import time

import requests
from flask import Flask, jsonify, request


class Quake:
    BASKET_SEND_TIME = 30  # sec
    SYNCHRONIZE_TIME = 2   # sec
    BASKET_SIZE = 1  # txs
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
        self.signer = PKCS1_v1_5.new(self.key)

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

        self.synchronize_timer = threading.Timer(Quake.SYNCHRONIZE_TIME, self.synchronize_txs)
        self.synchronize_timer.daemon = True

        # for debugging
        self.tx_requests_stats = {}

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
                response = requests.get('https://%s:%s/chain' % (self.host, self.port))
            except requests.RequestException as msg:
                help.print_log(msg, False, file_log=False)
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
        # help.print_log((self.hash, 'basket', len(self.tx_basket), 'valid', len(self.valid_tx), 'failed', len(self.failed_tx),
        #                 'voted', len(self.voted_tx), 'nbrs', main.dic_neighbours.keys(), 'nodes', len(main.dic_network_node)))
        if not by_timer and len(self.tx_basket) < Quake.BASKET_SIZE:
            return

        self.send_basket_timer.cancel()
        self.send_basket_timer = threading.Timer(Quake.BASKET_SEND_TIME, self.check_tx_basket)
        self.send_basket_timer.daemon = True
        self.send_basket_timer.start()

        threading.Thread(target=send_tx_basket, args=(main.dic_neighbours.copy(), self.tx_basket, self.hash)).start()

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey.encode())
        verifier = PKCS1_v1_5.new(key)
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
            if item not in main.dic_network_node:
                continue
            node = main.dic_network_node[item]
            result &= self.verify_signature(node[0], new_tx['signatures'][item], tx_hash)

        return result

    def check_tx(self, new_tx):
        response = False

        if 'signatures' not in new_tx:
            new_tx['signatures'] = {}

        if self.check_signatures(new_tx):
            # some additional verifications
            response = True

        response = response if self.valid_node else not response

        return response, new_tx

    def add_to_tx_list(self, new_tx, from_client=False, sender_node='', add_type=''):
        tx_hash = self.generate_tx_hash(new_tx)
        new_tx['hash'] = tx_hash.hexdigest()

        if from_client:
            # help.print_log((time.time(), 'receiver', self.hash, 'tx', new_tx['hash']), file_name='stats.log', file_log=False)
            f = open(new_tx['hash'] + '.log', 'w')
            f.write(str(time.time()))
            f.close()

        # for debugging
        if new_tx['hash'] not in self.tx_requests_stats:
            self.tx_requests_stats[new_tx['hash']] = {
                'requests': 0 if from_client else 1
            }
        else:
            self.tx_requests_stats[new_tx['hash']]['requests'] += 1

        if 'signatures' not in new_tx:
            new_tx['signatures'] = {}

        is_updated = True
        if new_tx['hash'] in self.valid_tx:
            is_updated = False

            for item in new_tx['signatures']:
                if item not in self.valid_tx[new_tx['hash']]['signatures']:
                    # is_updated = True
                    self.valid_tx[new_tx['hash']]['signatures'][item] = new_tx['signatures'][item]
        else:
            self.valid_tx[new_tx['hash']] = new_tx

            if self.hash not in self.valid_tx[new_tx['hash']]['signatures']:
                signature = self.signer.sign(tx_hash)
                self.valid_tx[new_tx['hash']]['signatures'][self.hash] = base64.b64encode(signature).decode()

        just_collected = False
        votes_ratio = len(self.valid_tx[new_tx['hash']]['signatures']) / len(main.dic_network_node)
        if votes_ratio > 2/3:
            is_updated = False

            if new_tx['hash'] not in self.voted_tx:
                just_collected = True
                self.voted_tx.append(new_tx['hash'])

                try:
                    f = open(new_tx['hash'] + '.log', 'r')
                except:
                    pass
                else:
                    start_time = f.readline()
                    help.print_log((self.hash, 'tx', new_tx['hash'], 'sequence', new_tx['sequence'], 'requests_number',
                                    self.tx_requests_stats[new_tx['hash']]['requests'], 'time',
                                    time.time() - float(start_time), 'signatures', len(self.valid_tx[new_tx['hash']]['signatures'])),
                                   file_name='stats.log', debug_mode=False)

        if from_client:
            tx_index = self.find_tx(new_tx['hash'])
            if tx_index == -1:
                self.tx_basket.append(new_tx)

        return is_updated, new_tx, new_tx['hash'], just_collected

    def add_to_failed_list(self, new_tx):
        new_tx['attempt'] = 0
        self.failed_tx.append(new_tx)

    def handle_tx_basket(self, tx_basket):
        old_tx_basket = []
        updated_tx_basket = []
        just_collected = False
        for new_tx in tx_basket['txs']:
            checked_tx = quake.check_tx(new_tx)
            if checked_tx[0]:
                is_updated, tmp_tx, tx_hash, just_collected = quake.add_to_tx_list(checked_tx[1], sender_node=tx_basket['node'], add_type='handle the basket')

                if is_updated:
                    updated_tx_basket.append(tmp_tx)
                # else:
                #     if tx_hash not in self.voted_tx:
                #         old_tx_basket.append(tmp_tx)
            else:
                quake.add_to_failed_list(checked_tx[1])

        if updated_tx_basket:
            send_tx_basket(main.dic_neighbours.copy(), updated_tx_basket, self.hash, just_collected=just_collected)

        if old_tx_basket:
            send_tx_basket(main.dic_neighbours, old_tx_basket, self.hash, exclude_neigbors=(tx_basket['node']), just_collected=just_collected)

    def request_tx_by_hash(self, tx_hash):
        for nbr in main.dic_neighbours:
            try:
                response = requests.get('http://%s:%s/tx/info' % (nbr[1], peer_port(nbr[2])), json={'hash': tx_hash})
            except requests.RequestException as msg:
                help.print_log(msg, False, file_log=False)
            else:
                if response.status_code != 200:
                    continue

                return json.loads(response.text)
        return {}

    def synchronize_txs(self):

        check_txs = {}
        valid_txs = self.valid_tx.copy()
        for item in valid_txs:
            if item not in self.voted_tx:
                check_txs[item] = valid_txs[item]

        if check_txs:
            txs_data = {
                'node': self.hash,
                'txs': check_txs,
            }
            neighbors = main.dic_neighbours.copy()

            for node_hash in neighbors:
                try:
                    response = requests.post('http://%s:%s/txs/update' % (neighbors[node_hash][1],
                                                                          peer_port(neighbors[node_hash][2])),
                                             json=txs_data)
                except requests.RequestException as msg:
                    help.print_log(msg, False, file_log=False)
                else:
                    if response.status_code == 200:
                        txs = json.loads(response.text)
                        for item in txs:
                            if item in self.valid_tx:
                                updated_tx = self.valid_tx[item].copy()
                                updated_tx['signatures'] = txs[item]
                                if self.check_signatures(updated_tx):
                                    self.add_to_tx_list(updated_tx, add_type='response from another node to synchronize request')

        self.synchronize_timer = threading.Timer(Quake.SYNCHRONIZE_TIME, self.synchronize_txs)
        self.synchronize_timer.daemon = True
        self.synchronize_timer.start()

    def txs_info(self, values):
        response = {}
        for item in values['txs']:
            result, new_tx = self.check_tx(values['txs'][item])

            if result:
                self.add_to_tx_list(values['txs'][item], sender_node=values['node'], add_type='request from another node to synchronize')

            if item in self.valid_tx:
                response[item] = self.valid_tx[item]['signatures']

        return response


app = Flask(__name__)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


def peer_port(c_port):
    return int(c_port) - Quake.PORT_DISTANCE


def check_required(required, received):
    if not all(k in received for k in required):
        return 'Missing values', 400
    return -1


def send_tx_basket(neighbors, basket, node_hash, exclude_neigbors=(), just_collected=False):
    txs_data = {
        'node': node_hash,
        'txs': basket,
        'just_collected': just_collected
    }

    is_sent = False
    for node_hash in neighbors:
        if node_hash in exclude_neigbors:
            continue

        try:
            response = requests.post('http://%s:%s/txs/basket' % (neighbors[node_hash][1],
                                                                  peer_port(neighbors[node_hash][2])), json=txs_data)
        except requests.RequestException as msg:
            help.print_log(msg, False, file_log=False)
        else:
            if response.status_code == 200:
                is_sent = True

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
    values = request.get_json(force=True)
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
        quake.add_to_tx_list(checked_tx[1], from_client=True, add_type='received from client')
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
    values = request.get_json(force=True)
    required = ['node', 'txs', 'just_collected']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    # TODO if the node is not in neighbor list already - notify in response (status code)

    # if values['just_collected']:
    # help.print_log((quake.hash, values['just_collected'], values['node']), file_log=False)

        # help.print_log((quake.hash, 'got it'), file_log=False)

    if len(values['txs']):
        threading.Thread(target=quake.handle_tx_basket, args=(values, )).start()

    return 'OK', 200


@app.route('/txs/update', methods=['POST'])
def txs_update():
    values = request.get_json(force=True)
    required = ['node', 'txs']
    check_result = check_required(required, values)
    if check_result != -1:
        return check_result

    # TODO if the node is not in neighbor list already - notify in response (status code)

    response = quake.txs_info(values)

    return jsonify(response), 200


@app.route('/tx/info', methods=['GET'])
def tx_info():
    values = request.get_json(force=True)

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
    parser.add_argument('-p', '--port', default=30001, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    parser.add_argument('-n', '--neighbors', default=4, type=int, help='set the number of neighbors')

    parser.add_argument('-q', '--quite', help='run in quite mode')
    parser.add_argument('-nv', '--non_valid_node', help="Emulate non-valid node", action="store_true")

    args = parser.parse_args()
    connect_host = args.connect_to_host
    connect_port = args.connect_to_port

    host = args.host
    port = args.port - Quake.PORT_DISTANCE
    main.port = str(args.port)

    main.run()

    quake.neighbors = args.neighbors

    quake.valid_node = not args.non_valid_node
    help.debug = not args.quite

    quake.host = connect_host
    quake.port = connect_port
    
    quake.update_chain()
    quake.synchronize_timer.start()
    quake.send_basket_timer.start()

    app.run(host=host, port=port)


if __name__ == '__main__':
    start()
