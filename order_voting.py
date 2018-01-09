

    voting_basket = []

    def add_to_voting_basket(self,tx_basket):
        # fill the voting basket with the valid transactions
        #while len(self.voting_basket) < Quake.BASKET_SIZE:

        #    self.voting_basket.append(tx_basket)                #fix
        print (tx_basket)
        return True

    def voting_basket_hash(self):
        return 'becbfbaeec7391ed01fb10ee0a11bec62c93a7ace36dfea9d0b37d9867f9d4' #blockchain.hash(last_block)  # fix

    def sign_basket(self):
        basket_signature =  self.key.sign(self.voting_basket_hash(), self.key)
        return  basket_signature

    def create_voting_block(self):
        last_block = self.blockchain.last_block
        last_block_hash = self.blockchain.hash(last_block)
        voting_basket_hash = self.voting_basket_hash()
        basket_signature = self.sign_basket()
        voting_block = {
            'transactions': self.voting_basket,
            'previous_block_hash': str(last_block_hash),
            'basket_hash': str(voting_basket_hash),
            'basket_signature':  str(basket_signature)
        }

        return voting_block

    def hash_voting_block(self, block):

        block_string = json.dumps(block, sort_keys=True).encode()
        print hashlib.sha256(block_string).hexdigest()
        return hashlib.sha256(block_string).hexdigest()

    def sign_voting_block(self, voting_block):
        #signs voting_block that means votes for it
     #   return self.key.sign(voting_block, self.key)
        pass

    def send_block_to_vote(self) 
        # sends block with voting basket and previous block hash to...
        print('sending data')
        send_data = create_voting_block()

        for node in self.neighbors_list:
            response = requests.post('http://%s/txs/basket' % node['address'], data=send_data)

#            if response.status_code == 200:
#                self.handle_tx_basket(response.text)

    def check_majority(self):
        pass

    def add_block_to_blockchain(self):
        pass

    
    
    
#Just a test function
@app.route('/test', methods=['GET'])
def test():
    block = quake.create_voting_block()
    quake.add_to_voting_basket(quake.tx_basket)
    quake.send_block_to_vote()
    return jsonify(block), 200



