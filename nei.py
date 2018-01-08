import threading 
import socket
import time
import json
import math
import hashlib
import sys
import random



class NaN:

	def __init__(self, conn, data):

		self.data = data
		self.conn = conn

	def connectRequestUpload (conn,publicKey,dic_network_node):

		msg = {'object':'node',
			   'hashKey':publicKey,
			   'action':'connect_fullList',
			   'data':dic_network_node
			   }
		msg = json.dumps(msg)
		conn.send(msg.encode())


	def connectRequestDownload(ip_request_node, port_request_node, publicKey):

		msg_send = {'object':'node',
					'hashKey':publicKey,
					'action':'connect',
					'data':'empty'}
		msg_send = json.dumps(msg_send).encode()

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip_request_node,int(port_request_node)))
		
		s.send(msg_send)
		data = s.recv(4096)
		if data:
			data = data.decode()
			data = json.loads(data)
			print(data)
			return data['data']
		else:
			s.close()



	def updateLun(node_id,info,publicKey,dic_neighbours,list_neighbours):

		msg = {'object':'node',
			   'hashKey':publicKey,
			   'action':'update_lun',
			   'data':[node_id,info[0],info[1]]
			   }
		msg = json.dumps(msg).encode()

		
		for i in list_neighbours:
			ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			host = dic_neighbours[i][0]
			port = dic_neighbours[i][1]
			ss.connect((host,int(port)))
			ss.send(msg)
			ss.close()


	def requestNei(dic_network_node,list_network_node,publicKey):


		while True:
			index = random.randint(0,len(list_network_node)-1)
			if index == list_network_node.index(publicKey):
				
				print ('SHIT!')
			else:
				break
		#print (index,list_network_node[index],dic_network_node[list_network_node[index]][0])
		host_node = dic_network_node[list_network_node[index]][0]
		port_node = int(dic_network_node[list_network_node[index]][1])

		msg = {'object':'node',
			   'hashKey':str(publicKey),
			   'action':'request_Nei',
			   'data':dic_network_node[publicKey]}
		msg = json.dumps(msg).encode()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host_node,port_node))
		
		s.send(msg)
		data = s.recv(4096)
		if data:
			data = data.decode()
			data = json.loads(data)
			print(data)
			if data['data'] == 'Yes':

				b = [1,list_network_node[index],host_node,port_node]
				print (b)

				return b
			elif data['data'] == 'No':
				c = [0,list_network_node[index],host_node,port_node]
				return c 
		else:
			s.close()
		

		pass

	def neighbour(conn,info, publicKey,list_neighbours):

		if len(list_neighbours) < 10:
			msg_send = {'object':'node',
				   'hashKey':publicKey,
				   'action':'request_Nei',
				   'data':'Yes'}
			msg_send = json.dumps(msg_send).encode()
			conn.send(msg_send)
			return 1

		else:
			msg_send = {'object':'node',
					   	'hashKey':publicKey,
					    'action':'request_Nei',
					    'data':'No'}
			msg_send = json.dumps(msg_send).encode()
			conn.send(msg_send)
			return 0 