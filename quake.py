import sys
from Crypto.PublicKey import RSA
from blockchain import Blockchain
from uuid import uuid4
import hashlib
import json
from operator import itemgetter

import requests
from flask import Flask, jsonify, request


class Quake:
    def __init__(self, neighbors=4):
        self.host = ''
        self.__port = ''
        self.neighbors = neighbors
        self.blockchain = Blockchain()

        self.key = RSA.generate(2048)

        self.identity = self.generate_identity()
        self.nodes = [self.identity]

        self.neighbors_list = []

        self.update_data()

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

    def generate_identity(self):
        pubkey = self.key.publickey()
        node_hash = hashlib.sha256('%s%s%s' % (pubkey, self.host, self.port))
        return {
            'hash': node_hash,
            'pubkey': pubkey,
            'address': self.host + self.port
        }

    def sort_nodes(self):
        self.nodes = sorted(self.nodes, key=itemgetter('hash'))


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


@app.route('/data', methods=['GET'])
def data():
    # Get the list of peers
    response = {'nodes': quake.nodes, 'chain': quake.blockchain.chain}

    return jsonify(response), 200


@app.route('/tx', methods=['POST'])
def tx():
    # Tx from client
    values = request.get_json()

    required = ['sender', 'receiver', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400

    index = quake.blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

    response = {
        'message': 'Transaction will be added to Block %s' % index,
    }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='host or url')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    parser.add_argument('-n', '--neighbors', default=4, type=int, help='set the number of neighbors')

    args = parser.parse_args()
    connect_host = args.connect_to_host
    connect_port = args.connect_to_port

    host = args.host
    port = args.port

    quake.neighbors = args.neighbors

    quake.nodes = connect_host
    quake.port = connect_port
    quake.update_data()

    app.run(host=host, port=port)
