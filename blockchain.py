from time import time
import json
import hashlib
from Crypto.Hash import SHA



class Blockchain(object):
    def __init__(self, key):
        self.chain = []
        self.current_transactions = []

        self.new_block(previous_hash=1)

        self.key = key
        self.voting_basket = []

    def new_block(self, previous_hash):
        """
        Create new Block in the Blockchain
        :param previous_hash: (Optional) <str> Hash of the previous Block
        :return: <dict> New Block
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Creates a new transaction to go into the next mined Block
        :param sender: <str> Address of the Sender
        :param recipient: <str> Address of the Recipient
        :param amount: <int> Amount
        :return: <int> The index of the Block
        """

        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1


    def add_to_voting_basket(self, valid_tx, basket_size):
        # fill the voting basket with the valid transactions
        #self.voting_basket =[]
        copy_valid_tx = sorted(valid_tx)[:basket_size]
        for item in copy_valid_tx:
            self.voting_basket.append(item)

        print self.voting_basket


    def voting_basket_hash(self):
        h = SHA.new()
        s = ''
        for item in self.voting_basket:
            s = s + str(item)
        h.update(s.encode())
        return h.hexdigest()

    def sign_basket(self):
        basket_signature =  self.key.sign(self.voting_basket_hash(), '')
        return  basket_signature

    def create_voting_block(self):
        voting_block = {
            'previous_block_hash': str(self.hash(self.last_block)),
            'transactions': self.voting_basket,
            'basket_hash': str(self.voting_basket_hash()),
            'basket_signature':  str(self.sign_basket()),
            'this_block_sign': '1',
            'node_sign': '1'
        }

        return voting_block


    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: <dict> Block
        :return: <str>
        """

        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]
