import sys
from blockchain import Blockchain
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


class Quake:
    def __init__(self, c_host=None, c_port=None):
        self.host = c_host
        self.port = c_port if ':%i' % c_port else ''
        self.nodes = []
        self.get_nodes()

    def get_nodes(self):
        if self.host:
            response = requests.get('https://%s%s' % self.host, self.port)
            if response.status_code == 200:
                self.nodes = response.json()


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()


@app.route('/nodes', methods=['GET'])
def nodes():
    # Get the list of peers
    response = {}

    return jsonify(response), 200


@app.route('/tx', methods=['POST'])
def tx():
    # Tx from client
    values = request.get_json()

    required = ['sender', 'receiver', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

    response = {'message': 'Transaction will be added to Block %s' % index}
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='host or url')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')

    parser.add_argument('-cH', '--connect_to_host', type=str, help='host to connect to')
    parser.add_argument('-cp', '--connect_to_port', type=int, help='port to connect to')

    args = parser.parse_args()
    connect_host = args.connect_host
    connect_port = args.connect_port

    quake = Quake(connect_host, connect_port)

    host = args.host
    port = args.port

    app.run(host=host, port=port)
