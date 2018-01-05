import sys
from quake import Quake
from blockchain import Blockchain
from uuid import uuid4

import requests
from flask import Flask, jsonify, request


def main():
    def get_connection_info():
        change_create = True
        change_host = True
        host = -1

        while True:
            if change_host:
                host = input("Host/IP-address (print [exit] to change quit): ")
                if host == 'exit':
                    continue
                elif len(host) == 0:
                    print('Try again')
                    continue
                elif host == 'exit':
                    print('Bye-bye\n')
                    sys.exit()
                else:
                    continue
            change_host = True

            port = input("Port (print [back] to change host): ")

            if port == 'back':
                continue
            elif len(port) == 0:
                print('Try again')
                change_host = False
                continue
            elif not port.isdigit() or int(port) < 1 or int(port) > 65535:
                print('Wrong value')
                change_host = False
                continue

            return host, int(port)

    while True:
        host, port = get_connection_info()

        quake = Quake(host, port)
        break


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
    port = args.port

    app.run(host='0.0.0.0', port=port)
