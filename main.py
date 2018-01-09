
from nei import NaN
import threading 
import socket
import time
import json
import math
import hashlib
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


# port = sys.argv[1]
port = 0
list_sockets = {}
list_addr = {}
th = {}


list_network_node = []
dic_network_node ={}

list_neighbours = []
dic_neighbours = {}




privateKey = RSA.generate(2048)
publicKey = privateKey.publickey().exportKey()

publicKey = hashlib.sha1(publicKey).hexdigest()


dic_network_node[str(publicKey)] = ['127.0.0.1',port]
list_network_node.append(str(publicKey))






list_actions = ['connect',
				 'update_lun',
				 'tx',
				 'init_voting',
				 'check_voting',
				 'check_order',
				 'init_order',
				 'request_Nei']

list_sub_actions =['newNode',
				   'fullList']

list_node = ['node',
			 'client']

class mainNei:




	def __init___(self):
		pass


	def updateLun(self,node_id,info):
		if node_id in list_network_node:
			print('The Node is already in the UNL\n')
		else:
			list_network_node.append(node_id)
			dic_network_node[node_id] = info
			NaN.updateLun(node_id,info,publicKey,dic_neighbours,list_neighbours)



	def checkStatus(self):

	#cn = input('Do you want to connect to network?Y/n\n')
	#if cn == 'Y':


		while True:
			if len(list_network_node)<2:
				#ip_request_node = input('Type IP address of Node\n')
				#port_request_node = input('Type Port of Node\n')
				ip_request_node = '127.0.0.1'
				port_request_node =50001
				dic_network_node_temp = NaN.connectRequestDownload(ip_request_node,port_request_node,publicKey)
				dic_network_node.update(dic_network_node_temp)
				print (dic_network_node)
				if dic_network_node:
					list_network_node.clear()
					for i in dic_network_node:
						list_network_node.append(i)

					while len(list_neighbours) < 4:
						code = NaN.requestNei(dic_network_node,list_network_node,publicKey)
						if code[0] == 1 :
							dic_neighbours[code[1]] = [code[2],code[3]]
							list_neighbours.append(code[1])
							print ('Neighbours: ', dic_neighbours)
							time.sleep(3)

						else:
							print ('Something wrong\n')
							print ('\n')
							print ('\n')
							print ('Neighbours: ', dic_neighbours)
							print ('\n')
							print ('\n')
							print ('Neighbours: ', list_neighbours)
							time.sleep(3)
				else:
					pass
			else:
				break

	#else:
	#	pass

	def nanUnl(self, code_request):
		if code_request == 1:
			return dic_neighbours
		elif code_request == 2:
			return dic_network_node

	def main(self,conn,addr):

		while True:
			data = conn.recv(4096).decode()
			data = json.loads(data)
			if data:
				if data['object'] =='node':
					node_id = data['hashKey']
					info = data['data']
					print(node_id)
					print('__________')
					print (list_neighbours)
					print ('\n')
					print ('\n')
					print ('\n')
					print (dic_neighbours)
					print ('-----')
					print('THis is an ', info)
					class_method = list_actions.index(data['action'])

					if class_method == 0:

						NaN.connectRequestUpload(conn,publicKey,dic_network_node)
						

					elif class_method == 1:
						id_newNode = info[0]
						info = [info[1],info[2]]
						self.updateLun(id_newNode, info)
					

					elif class_method == 7:
						if node_id in list_neighbours:
							msg_send = {'object':'node',
						   	'hashKey':publicKey,
						    'action':'request_Nei',
						    'data':'No'}
							msg_send = json.dumps(msg_send).encode()
							conn.send(msg_send)
							print ("The Node is already a neighbour\n")
							print (dic_neighbours)
							time.sleep(3)
						else:
							code = NaN.neighbour(conn, info, publicKey,list_neighbours)
							if code == 1:
								dic_neighbours[node_id]=info
								print ('Excellent New Nei!!!!', dic_neighbours)
								list_neighbours.append(node_id)
								time.sleep(3)

								th_newNode = threading.Thread(target = self.updateLun, args =(node_id,info))
								th_newNode.start()
							elif code == 0:
								print ("The list is already full\n")

					conn.close()
					break

				else:
					break
			else:
				break	

		


	def listen(self, port):

		serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

		host = '127.0.0.1'
		#port = 50001
		print(port)
		serversocket.bind((host,int(port)))
		serversocket.listen(5)

		i = 1
		while th_main.isAlive():
			
			for j in range(i,i+1):
				list_sockets[j],list_addr[j] = serversocket.accept()
				th[j] = threading.Thread(target = self.main, args=(list_sockets[j],list_addr[j]))
				th[j].start()
				print ("created new thread: Thread-{0}".format(j))
				print ("Number of active threading: ", threading.activeCount())
			
			i = i + 1
		serversocket.close()

th_main = None
th_init = None
def run():
	global th_main
	global th_init
	global dic_network_node
	dic_network_node[str(publicKey)][1] = port
	main_nei = mainNei()
	th_main = threading.Thread(target=main_nei.listen, args = (port,) )
	th_main.daemon = True
	th_main.start()


	if port != '50001':
		th_init = threading.Thread(target = main_nei.checkStatus, args= ())
		th_init.daemon = True
		th_init.start()

	else:
		pass

	# th_main.join()
	#th_init.join()


if __name__ == '__main__':
	port = sys.argv[1]
	run()