from argparse import ArgumentParser
from multiprocessing import Pool
import binascii, os, sys, requests, json, threading, time

parser = ArgumentParser()

parser.add_argument('-H', '--host', default='127.0.0.1', type=str, help='ip to send tx to (127.0.0.1 by default)')
parser.add_argument('-a', '--amount', default=10, type=int, help='the number of nodes to run')

args = parser.parse_args()
amount = args.amount

for i in range(amount):
    port_arg = 30001 + i
    threading.Thread(target=os.system, args=('python3 quake.py -p ' + str(port_arg), )).start()
    time.sleep(1)

