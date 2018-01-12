from time import time
import json
import hashlib, base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Blockchain(object):
    def __init__(self, key, signer, node_hash):
        self.chain = []
        self.current_transactions = []
        self.hash = node_hash
        self.key = key
        self.signer = signer
        self.voting_basket = []

        self.new_block(previous_hash=1)
        self.voting_block_hash = ''  # hash
        self.known_voting_blocks = {}  # {block_hash: {some data}} # TODO add round info

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

    def add_to_voting_basket(self, voted_tx, basket_size):
        # fill the voting basket with the valid transactions
        #  self.voting_basket =[]
        self.voting_basket = voted_tx[:basket_size]
        self.voting_block_hash = self.voting_basket_hash()
        self.known_voting_blocks[self.voting_block_hash] = self.create_voting_block()

        print(self.voting_basket)

    def voting_basket_hash(self):
        h = SHA.new()
        s = ''

        for item in self.voting_basket.copy():
            s = s + str(item)

        h.update(s.encode())
        return h.hexdigest()

    def sign_basket(self, round_number):
        h = SHA.new()
        h.update((self.voting_block_hash + self.last_block + self.hash(self.last_block) + str(round_number)).encode())
        basket_signature = self.signer.sign(h)
        return base64.b64encode(basket_signature).decode()

    def create_voting_block(self, round_number=0):
        voting_block = {
                'previous_block_hash': self.hash(self.last_block),
                'transactions': self.voting_basket,
                'basket_signatures': {self.hash: str(self.sign_basket(round_number))},
                'round': round_number,
        }

        return voting_block

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey.encode())
        verifier = PKCS1_v1_5.new(key)
        return verifier.verify(tx_hash, base64.b64decode(signature.encode()))

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


