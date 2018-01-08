
    voting_basket = []

    def add_to_voting_basket(self,tx_basket):
        # fill the voting basket with the valid transactions
        while len(self.voting_basket) < Quake.BASKET_SIZE:
            self.voting_basket.append(tx_basket)
        return True

    def voting_basket_hash(self):
        return 0 #blockchain.hash(last_block)  # remake!!!

    def create_voting_block(self):
        last_block = self.blockchain.last_block
        last_block_hash = self.blockchain.hash(last_block)
        voting_basket_hash = self.voting_basket_hash()
        basket_signature = self.key.sign(self,voting_basket_hash) #self.key.sign(voting_basket_hash)
        voting_block = {
            'transactions': self.voting_basket,
            'previous_block_hash': str(last_block_hash),
            'basket_hash': str(voting_basket_hash),
            'basket_signature':  str(type(basket_signature))
        }

        return voting_block

    def sign_voting_block(self, voting_block):
        #signs voting_block that means votes for it
        return self.key.sign(voting_block)


    def send_block_to_vote(self, voting_block, voting_block_signature):
        # sends block with voting basket and previous block hash to...
        pass

    def check_majority(self):
        pass

    def add_block_to_blockchain(self):
        pass


#Just a test function
@app.route('/test', methods=['GET'])
def test():
    block = quake.create_voting_block()
    return jsonify(block), 200

