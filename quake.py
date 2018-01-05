import sys
from blockchain import Blockchain
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


class Quake:
    def __init__(self, host, port):
        self.host = host
        self.port = port


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')
blockchain = Blockchain()


@app.route('/nodes', methods=['GET'])
def nodes():
    # Get the list of peers
    response = ['hello', 'there']

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='host or url')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    host = args.host
    port = args.port

    app.run(host=host, port=port)