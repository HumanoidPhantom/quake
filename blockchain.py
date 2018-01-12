from time import time
import json
import hashlib, base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA


class Blockchain(object):
    def __init__(self, key, signer, node_hash):
        self.chain = []
        self.new_block([], 1, 0)

        self.hash = node_hash
        self.key = key
        self.signer = signer

        self.voting_basket = []
        self.voting_block_hash = ''  # hash
        self.known_voting_blocks = {}  # {block_hash: {some data}} # TODO add round info
        self.active_round = 0
        self.no_change_requests = 0

    def new_block(self, transactions, previous_hash, round_number):
        block = {
            'index': len(self.chain) + 1,
            'transactions': transactions,
            'round': round_number,
            'previous_hash': previous_hash or self.hash(self.chain[-1])
        }

        self.chain.append(block)
        return block

    def add_to_voting_basket(self, voted_tx, basket_size, round_number=0):
        # fill the voting basket with the valid transactions
        #  self.voting_basket =[]
        self.voting_basket = voted_tx[:basket_size]
        self.voting_block_hash = self.voting_basket_hash(self.voting_basket.copy())
        self.known_voting_blocks[self.voting_block_hash] = self.create_voting_block(round_number)

        print(self.voting_basket)

    def voting_basket_hash(self, tx_basket):
        h = SHA.new()
        s = ''

        for item in tx_basket:
            s = s + str(item)

        h.update(s.encode())
        return h.hexdigest()

    def generate_full_basket_hash(self, block_hash, last_block_hash, round_number):
        h = SHA.new()
        h.update((block_hash + last_block_hash + str(round_number)).encode())
        return h

    def sign_basket(self, round_number):
        basket_signature = self.signer.sign(self.generate_full_basket_hash(self.voting_block_hash,
                                            self.hash(self.last_block), str(round_number)))
        return base64.b64encode(basket_signature).decode()

    def create_voting_block(self, round_number=0):
        voting_block = {
                'previous_block_hash': self.hash(self.last_block),
                'transactions': self.voting_basket,
                'basket_signatures': {round_number: {self.hash: str(self.sign_basket(round_number))}},
        }

        return voting_block

    def verify_signature(self, pubkey, signature, tx_hash):
        key = RSA.importKey(pubkey.encode())
        verifier = PKCS1_v1_5.new(key)
        return verifier.verify(tx_hash, base64.b64decode(signature.encode()))

    def start_new_blockchain_round(self):
        self.active_round = 0
        self.no_change_requests = 0
        self.voting_block_hash = ''
        self.voting_basket = []
        self.known_voting_blocks = {}

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


