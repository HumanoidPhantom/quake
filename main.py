
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

MIN_NEIGHBORS = 4

list_network_node = []
dic_network_node ={}

list_neighbours = []
dic_neighbours = {}




privateKey = RSA.generate(2048)
publicKey1 = privateKey.publickey().exportKey()

publicKey = hashlib.sha1(publicKey1).hexdigest()


dic_network_node[str(publicKey)] = [publicKey1.decode(),'127.0.0.1',port]
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
			#print('The Node is already in the UNL\n')
			pass
		else:
			list_network_node.append(node_id)
			dic_network_node[node_id] = info
			NaN.updateLun(node_id,info,publicKey,dic_neighbours,list_neighbours)



	def checkStatus(self, ipaddr_to_connect='127.0.0.1'):

	#cn = input('Do you want to connect to network?Y/n\n')
	#if cn == 'Y':


		while True:
			if len(list_network_node)<2:
				#ip_request_node = input('Type IP address of Node\n')
				#port_request_node = input('Type Port of Node\n')
				ip_request_node = ipaddr_to_connect
				port_request_node =30001
				dic_network_node_temp = NaN.connectRequestDownload(ip_request_node,port_request_node,publicKey)
				dic_network_node.update(dic_network_node_temp)
				#print (dic_network_node)
				if dic_network_node:
					list_network_node.clear()
					for i in dic_network_node:
						list_network_node.append(i)

					while len(list_neighbours) < MIN_NEIGHBORS:
						code = NaN.requestNei(dic_network_node,list_network_node,publicKey)
						if code:
							if code[0] == 1 :
								dic_neighbours[code[1]] = [code[4],code[2],code[3]]
								list_neighbours.append(code[1])
								#print ('Neighbours: ', dic_neighbours)
							#	time.sleep(1)

							else:
								#print ('Something wrong\n')
								#print ('\n')
								#print ('\n')
								#print ('Neighbours: ', dic_neighbours)
								#print ('\n')
								#print ('\n')
								#print ('Neighbours: ', list_neighbours)
								time.sleep(1)
							of = open('text{0}.log'.format(port),'a')
							of.write(str(dic_neighbours)+' The length: '+str(len(dic_neighbours))+'\n\n')
							of.close()
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
			data =''
			while True:
				tmp = conn.recv(4096).decode()
				if tmp[-2:] == '}\n':
					data +=tmp
					break
				else:
					data += tmp

			if data:
				data = json.loads(data)
				if data['object'] =='node':
					node_id = data['hashKey']
					info = data['data']
					#print(node_id)
					#print('__________')
					#print (list_neighbours)
					#print ('\n')
					#print ('\n')
					#print ('\n')
					#print (dic_neighbours)
					#print ('-----')
					#print('THis is an ', info)
					class_method = list_actions.index(data['action'])

					if class_method == 0:

						NaN.connectRequestUpload(conn,publicKey,dic_network_node)


					elif class_method == 1:
						id_newNode = info[0]
						info = [info[1],info[2],info[3]]
						self.updateLun(id_newNode, info)


					elif class_method == 7:
						if node_id in list_neighbours:
							msg_send = {'object':'node',
						   	'hashKey':publicKey,
						    'action':'request_Nei',
						    'data':'No'}
							msg_send = (json.dumps(msg_send)+'\n').encode()
							conn.send(msg_send)
							#print ("The Node is already a neighbour\n")
							#print (dic_neighbours)
							#time.sleep(3)
						else:
							code = NaN.neighbour(conn, info, publicKey,list_neighbours)
							if code == 1:
								dic_neighbours[node_id]=info
								#print ('Excellent New Nei!!!!', dic_neighbours)
								list_neighbours.append(node_id)
								#time.sleep(3)

								th_newNode = threading.Thread(target = self.updateLun, args =(node_id,info))
								th_newNode.start()
							elif code == 0:
								#print ("The list is already full\n")
								of = open('text{0}.log'.format(port),'a')
								of.write(str(dic_neighbours)+' The length: '+str(len(dic_neighbours))+'\n\n')
								of.close()
					conn.close()
					break

				else:
					break
			else:
				break

		


	def listen(self, port, host_val='127.0.0.1', ipaddr_to_connect='127.0.0.1'):

		serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)

		host = host_val
		#port = 30001
		try:
			serversocket.bind((host,int(port)))
			serversocket.listen(5)
			if port != '30001':
				th_init = threading.Thread(target = main_nei.checkStatus, args= (ipaddr_to_connect,))
				th_init.start()
			else:
				pass
			i = 1
			while th_main.isAlive():

				for j in range(i,i+1):
					list_sockets[j],list_addr[j] = serversocket.accept()
					th[j] = threading.Thread(target = self.main, args=(list_sockets[j],list_addr[j]))
					th[j].start()
					#print ("created new thread: Thread-{0}".format(j))
					#print ("Number of active threading: ", threading.activeCount())

				i = i + 1
			serversocket.close()
		except  OSError as err:
			#print("OS error port {1}: {0}".format(err,port))
			sys.exit()


th_main = None
th_init = None
main_nei = mainNei()
ipaddr = ''
ipaddr_to_connect = ''
def run():
	global th_main
	global th_init
	global main_nei
	global dic_network_node
	dic_network_node[str(publicKey)][2] = port
	dic_network_node[str(publicKey)][1] = ipaddr
	th_main = threading.Thread(target=main_nei.listen, args=(port,ipaddr, ipaddr_to_connect))
	th_main.daemon = True
	th_main.start()

	# if port != '30001':
	#	if th_main.isAlive() :
	#		print ('Main thread is ready! {0}\n'.format(port))
	#		th_init = threading.Thread(target = main_nei.checkStatus, args= ())
	#		th_init.start()
	#	else:
	#		print('The node is not able to start!: {0}\n'.format(port))

	##	pass


if __name__ == '__main__':
	port = sys.argv[1]
	run()
	th_main.join()