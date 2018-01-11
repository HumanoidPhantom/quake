import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
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

        self.host = ''a
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

    def generate_node_hash(self, pubkey):
        return hashlib.sha256(('%s%s%s' % (pubkey, self.host, self.port)).encode())

    def generate_tx_hash(self, new_tx):
        return hashlib.sha256(('%s%s%s%s' % (new_tx['sender'], new_tx['receiver'], new_tx['amount'], new_tx['sequence'])))

    def generate_identity(self):
        pubkey = self.key.publickey().exportKey()
        node_hash = self.generate_node_hash(pubkey)
        return {
            'hash': node_hash,
            'pubkey': pubkey,
            'address': self.host + self.port
        }

    def sort_nodes(self):
        self.nodes = sorted(self.nodes, key=itemgetter('hash'))

    def check_hash(self, identity):
        # fix
        node_hash = self.generate_node_hash(identity['pubkey'])

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
            response = requests.post('http://%s/txs/basket' % node['address'], data=txs_data)

            if response.status_code == 200:
                self.handle_tx_basket(response.text)

        self.check_tx_basket()

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey)
        return key.verify(tx_hash, signature)

    def find_node(self, node_hash):
        nodes = [item for item in self.nodes if item['hash'] == node_hash]
        if len(nodes):
            return nodes[0]

        return None

    def find_tx(self, tx_hash):
        txs = [index for index in range(len(self.tx_basket)) if self.tx_basket[index]['hash'] == tx_hash]

        if len(txs):
            return txs[0]

        return -1

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

        response = response if self.valid_node else not response

        return response, new_tx

    def add_to_tx_basket(self, new_tx):
        tx_hash = self.generate_tx_hash(new_tx)
        new_tx['hash'] = tx_hash
        signature = self.key.sign(tx_hash)

        tx_index = self.find_tx(tx_hash)
        if tx_index == -1:
            new_tx['cur_signature'] = signature
            self.tx_basket.append(tx)
        else:
            new_tx['signatures'] += \
                [item for item in self.tx_basket[tx_index]['signatures'] if item not in new_tx['signatures']]

    def add_to_failed_list(self, new_tx):
        new_tx['attempt'] = 0
        self.failed_tx.append(new_tx)

    def handle_tx_basket(self, tx_basket):
        required = ['node', 'txs']
        check_result = check_required(required, tx_basket)
        if check_result != -1:
            return check_result

        for new_tx in tx_basket['txs']:
            checked_tx = quake.check_tx(new_tx)
            if checked_tx[0]:
                quake.add_to_tx_basket(checked_tx[1])
            else:
                quake.add_to_failed_list(checked_tx[1])


#-------------my part----------

    #valid_tx = {1: 1, 2: 2, 3: 3, 4:4, 5: 1, 6: 2, 7: 3, 8:4,9: 1, 10: 2, 11: 3, 12:4,13: 1, 14: 2, 15: 3, 16:4, 17: 1, 18: 2, 19: 3, 20:4, 21:21}
    valid_tx = {'45bd99d8a500472802328ed68a0b35c42471afae': {'sender': '93c098297b6087d22701', 'sequence': 6, 'hash': '45bd99d8a500472802328ed68a0b35c42471afae', 'amount': 1, 'signatures': {'82e1ed389ef44782b069ae0ecf5998a1b85dc620': 'MXLk56hOwzE2KTaNNID1IQOdDBYdaNcVYPtZ92ojsE54fOplvyFBAp+mrKkpfEYby9EMcCWXiC6pU9htiI7CN8Z/nK2HNWKGvvXzBm6Bxf3Z6I9yyxgsT8wJFuNA1ERnLhpqBz6QudQhP3qWtaLzmBUmjQD448ZXFuD4BDcguM4JTVQaEMcyFX5I4tBujOSVR4N9Vo12L5/Jtr39rnF0HUeHdgSScEG/Cf5iYZLrs//hnsBieQfG7PMXmOLhNT+WyGV/xATuBSgY63qP2CyrvfN0fKQwtJWWhUMERyahXb2iHNwW3ORCbZMbnTfUqD15FqxxHKYavBIsrLSqDuolJw==', '984c862dbdef73d5c94ee272810fd4de5a28a91f': 'R4xm/yC+zYxAmYcsadAyUTLgL0N9nEKA51Vcy0B7rvo90IEK6Cc2HFaOOOHmujvcN0STogv3pqFk1ULSo33nG9TdrXCJieskPS+vYR0a0Y6Bimt025fFeP2LUYF74Lm+21hmCPDCaHV+DvvMJVJ57SCEdn+7OkgsmZAyKPr7z16C14R0Vg/CMQQeIG4m9ictVydFMahgnXthI8HNs902mNVsUoihm08qqWJBW+icnQv26iz0onjuVwlPOfAYBO+P68rlNU6qe22TTHeYfhDjxWvEE0D2MGp8q7I4AqYIYoWkPbOqvadzrbSit6jIWMueSpGIdRuWWXrKpt9d8WLXyg==', 'b0967083f77c7736e1baa6030c7e7cb7969a31af': 'D21wSrCNjJwCtBp30TEOBfoSsd6cvSdieIG/8w7/3vOAEgSuaFs+4VUQ0z4GYcWJ4uh5yIj7pY9S+2GMAnNtHE4FwKHXyol04hw7X2otJzaaa0HCQnYH27+BMe7D11tnlcuWh87wvZaotJ9Qfiueb9Zr5/j6oQVlQ5KeslNhCN5hKplLE4m8ukFTuSU3c7rd7EhoObNkg8et9wu3r7AtCom+qpkMa2hYvw8S+793BxVKUUcE3nC9kDxJwuDs01jFhdkBrebEMmqf07oNccRNUQQPovRh+CMpO9iSnse3tmRIUhXMOL42/q3zUlVxmUBTPeMb8Y55kYrY0hXOYjU+6g=='}, 'receiver': 'alsdkjf'}, '45bd99d8a500472802328ed68a0b35c42471afae': {'sender': '93c098297b6087d22701', 'sequence': 6, 'hash': '45bd99d8a500472802328ed68a0b35c42471afae', 'amount': 1, 'signatures': {'82e1ed389ef44782b069ae0ecf5998a1b85dc620': 'MXLk56hOwzE2KTaNNID1IQOdDBYdaNcVYPtZ92ojsE54fOplvyFBAp+mrKkpfEYby9EMcCWXiC6pU9htiI7CN8Z/nK2HNWKGvvXzBm6Bxf3Z6I9yyxgsT8wJFuNA1ERnLhpqBz6QudQhP3qWtaLzmBUmjQD448ZXFuD4BDcguM4JTVQaEMcyFX5I4tBujOSVR4N9Vo12L5/Jtr39rnF0HUeHdgSScEG/Cf5iYZLrs//hnsBieQfG7PMXmOLhNT+WyGV/xATuBSgY63qP2CyrvfN0fKQwtJWWhUMERyahXb2iHNwW3ORCbZMbnTfUqD15FqxxHKYavBIsrLSqDuolJw==', '984c862dbdef73d5c94ee272810fd4de5a28a91f': 'R4xm/yC+zYxAmYcsadAyUTLgL0N9nEKA51Vcy0B7rvo90IEK6Cc2HFaOOOHmujvcN0STogv3pqFk1ULSo33nG9TdrXCJieskPS+vYR0a0Y6Bimt025fFeP2LUYF74Lm+21hmCPDCaHV+DvvMJVJ57SCEdn+7OkgsmZAyKPr7z16C14R0Vg/CMQQeIG4m9ictVydFMahgnXthI8HNs902mNVsUoihm08qqWJBW+icnQv26iz0onjuVwlPOfAYBO+P68rlNU6qe22TTHeYfhDjxWvEE0D2MGp8q7I4AqYIYoWkPbOqvadzrbSit6jIWMueSpGIdRuWWXrKpt9d8WLXyg==', 'b0967083f77c7736e1baa6030c7e7cb7969a31af': 'D21wSrCNjJwCtBp30TEOBfoSsd6cvSdieIG/8w7/3vOAEgSuaFs+4VUQ0z4GYcWJ4uh5yIj7pY9S+2GMAnNtHE4FwKHXyol04hw7X2otJzaaa0HCQnYH27+BMe7D11tnlcuWh87wvZaotJ9Qfiueb9Zr5/j6oQVlQ5KeslNhCN5hKplLE4m8ukFTuSU3c7rd7EhoObNkg8et9wu3r7AtCom+qpkMa2hYvw8S+793BxVKUUcE3nC9kDxJwuDs01jFhdkBrebEMmqf07oNccRNUQQPovRh+CMpO9iSnse3tmRIUhXMOL42/q3zUlVxmUBTPeMb8Y55kYrY0hXOYjU+6g=='}, 'receiver': 'alsdkjf'} }
    voting_basket = []

    def add_to_voting_basket(self):
        # fill the voting basket with the valid transactions
        #self.voting_basket =[]
        copy_valid_tx = sorted(self.valid_tx)[:Quake.BASKET_SIZE]
        for item in copy_valid_tx:
            self.voting_basket.append(item)

        print self.voting_basket


    def voting_basket_hash(self):

        h = SHA.new()
        s = ''
        for item in self.voting_basket:
            s = s + str(item)
        h.update(s.encode())
        #print 'basket_hash is ' + h.hexdigest()
        return h.hexdigest()

    def sign_basket(self):
        basket_signature =  self.key.sign(self.voting_basket_hash(), '')
        #print 'basket signature is' + str(basket_signature)
        return  basket_signature


    def create_voting_block(self):
        voting_block = {
            'previous_block_hash': str(self.blockchain.hash(self.blockchain.last_block)),
            'transactions': self.voting_basket,
            'basket_hash': str(self.voting_basket_hash()),
            'basket_signature':  str(self.sign_basket()),
            'this_block_sign': '1',
            'node_sign': '1'
        }

        return voting_block

#    def hash_voting_block(self, block):
#
#        block_string = json.dumps(block, sort_keys=True).encode()
#        print block_string
#        print (hashlib.sha256(block_string).hexdigest())
#        return hashlib.sha256(block_string).hexdigest()

#    def sign_voting_block(self, voting_block):
#        #signs voting_block that means votes for it
#        #return self.key.sign(voting_block, self.key)
#        pass


    def send_voting_block(neighbors, voting_block, node_hash, exclude_neigbors=()):
        # sends block with voting basket and previous block hash to...
        for node_hash in neighbors:
            if node_hash in exclude_neigbors:
                continue

            try:
                response = requests.post('http://%s:%s/voting_block' % (neighbors[node_hash][1],
                                                                      peer_port(neighbors[node_hash][2])),
                                         json=voting_block)
            except requests.RequestException as msg:
                help.print_log(msg, False)
            else:
                if response.status_code == 200:
                    is_sent = True

        if is_sent:
            quake.voting_basket = []


    def check_majority(self):
        pass




#------------------------------

app = Flask(__name__)

node_identifier = str(uuid4()).replace('-', '')

quake = Quake()


def check_required(required, received):
    if not all(k in received for k in required):
        return 'Missing values', 400
    return -1

#----------------my part------------

#Just a test function
@app.route('/test', methods=['GET'])
def test():
    voting_block = quake.create_voting_block()
    quake.add_to_voting_basket()
    #quake.send_block_to_vote()
    return jsonify(voting_block), 200




#------------------------------------

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

    checked_tx = quake.check_tx(new_tx)
    if checked_tx[0]:
        quake.add_to_tx_basket(checked_tx[1])
        quake.check_tx_basket()
    else:
        quake.add_to_failed_list(checked_tx[1])

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

    quake.handle_tx_basket(values)
    quake.check_tx_basket()

    response = {
        'node': quake.identity['hash'],
        'txs': quake.tx_basket,
    }

    return jsonify(response), 200


def main():
    from argparse import ArgumentParser

    parser = ArgumentParser()

    parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip or url')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    parser.add_argument('-sp', '--socket-port', default=50000, type=int, help='port for socket to listen on')

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
