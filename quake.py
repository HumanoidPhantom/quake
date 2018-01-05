import sys
from blockchain import Blockchain
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


class Quake:
    def __init__(self):
        self.host = ''
        self.__port = ''
        self.nodes = []
        self.get_nodes()

    @property
    def port(self):
        return self.__port

    @port.setter
    def port(self, c_port):
        self.__port = ':%i' % c_port if c_port else ''

    def get_nodes(self):
        if self.host:
            response = requests.get('https://%s%s' % (self.host, self.port))
            if response.status_code == 200:
                self.nodes = response.json()


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()
quake = Quake()


@app.route('/nodes', methods=['GET'])
def nodes():
    # Get the list of peers
    response = quake.nodes

    return jsonify(response), 200


@app.route('/tx', methods=['POST'])
def tx():
    # Tx from client
    values = request.get_json()

    required = ['sender', 'receiver', 'amount']

    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_transaction(values['sender'], values['receiver'], values['amount'])

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

    args = parser.parse_args()
    connect_host = args.connect_to_host
    connect_port = args.connect_to_port

    host = args.host
    port = args.port

    quake.nodes = connect_host
    quake.port = connect_port
    quake.get_nodes()

    app.run(host=host, port=port)
