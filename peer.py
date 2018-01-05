import json



class Peer(object):

    def __init__(self, neighbours_number=4):
        self.neighbours = []
        self.neighbours_number = neighbours_number

    def add_peer(self):
        pass

    def connect(self, address):
        pass

    def update_lun(self):
        pass

    def check_tx(self, tx):
        """
        :param tx: <str>
        :return: <bool> True|False
        """

        result = False

        return result

    def add_to_basket(self):
        pass

    def check_round_state(self):
        pass

    def check_basket_size(self):
        pass

    def send_basket(self):
        pass

    def receive_basket(self):
        pass

    def check_voting_round_status(self):
        pass

    def check_signs(self):
        pass

    def init_voting(self):
        pass

    def check_voting(self):
        pass

    def init_order(self):
        pass

    def check_order(self):
        pass
