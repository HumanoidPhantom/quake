from argparse import ArgumentParser
from subprocess import Popen

import binascii, os, sys, requests, json, threading, time

parser = ArgumentParser()

parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip to send tx to (127.0.0.1 by default)')
parser.add_argument('-a', '--amount', default=10, type=int, help='the number of nodes to run')

parser.add_argument('-s', '--start_port', default=30001, type=int, help='run nodes starting from port')

args = parser.parse_args()
amount = args.amount
start_port = args.start_port

proc = None

for i in range(amount):
    port_arg = start_port + i
    print('starting', port_arg)
    proc = Popen(['python3', 'quake.py', '-p', str(port_arg)])
    # threading.Thread(target=os.system, args=('python3 quake.py -p ' + str(port_arg), )).start()
    time.sleep(1)

print('done')

if proc:
    proc.wait()


