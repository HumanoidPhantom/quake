from argparse import ArgumentParser
import binascii, os, sys, requests, json

parser = ArgumentParser()

parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip to send tx to (127.0.0.1 by default)')
parser.add_argument('-p', '--port', default=29001, type=int, help='port (49001 by default)')

parser.add_argument('-s', '--sender', default='', type=str, help='Sender address (hex string)')

args = parser.parse_args()

host = args.host
port = args.port

sender = args.sender if args.sender != '' else binascii.b2a_hex(os.urandom(10)).decode()
sequence = 0


def send():
    global sequence

    receiver = input('Enter receiver address or press Enter to use random value: ')
    messages_number = input('The number of messages to send at once: ')

    try:
        messages_number = int(messages_number)
    except ValueError:
        messages_number = 1

    for i in range(messages_number):
        tx = {
            'sender': sender,
            'receiver': receiver if receiver else binascii.b2a_hex(os.urandom(10)).decode(),
            'amount': 1,
            'sequence': sequence
        }
        response = requests.post('http://%s:%s/tx' % (host, port), json=tx)

        print(response.status_code, response.text)
        if response.status_code == 200:
            sequence += 1


print('Your address: ' + sender)
while True:
    command = input('Enter the command ([send], [quit]): ')
    if command == 'send':
        send()
    elif command == 'quit':
        print('Bye')
        sys.exit()
