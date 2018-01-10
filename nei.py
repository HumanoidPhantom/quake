import threading 
import socket
import time
import json
import math
import hashlib
import sys
import random

MAX_NEIGHBORS = 20


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
		msg = json.dumps(msg)+'\n'
		conn.send(msg.encode())


	def connectRequestDownload(ip_request_node, port_request_node, publicKey):

		msg_send = {'object':'node',
					'hashKey':publicKey,
					'action':'connect',
					'data':'empty'}
		msg_send = (json.dumps(msg_send)+'\n').encode()

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((ip_request_node,int(port_request_node)))
			s.send(msg_send)
			data =''
			while True:
				tmp = s.recv(4096).decode()
				if tmp[-2:] == '}\n':
					data +=tmp
					break
				else:
					data += tmp
			if data:
				data = data
				data = json.loads(data)
				#print(data)
				return data['data']
			else:
				s.close()
		except  OSError as err:
			#print("OS error {1}: {0}".format(err,port_request_node))
			pass

		except ConnectionRefusedError:
			of = open('log_{0}'.format(publicKey),'a')
			of.write('ConnectionRefusedError {0}\n'.format(port_request_node))
			of.close()


	def updateLun(node_id,info,publicKey,dic_neighbours,list_neighbours):

		msg = {'object':'node',
			   'hashKey':publicKey,
			   'action':'update_lun',
			   'data':[node_id,info[0],info[1],info[2]]
			   }
		msg = (json.dumps(msg)+'\n').encode()

		
		for i in list_neighbours:
			ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			host = dic_neighbours[i][1]
			port = dic_neighbours[i][2]
			try:
				ss.connect((host,int(port)))
				ss.send(msg)
				ss.close()
			except  OSError as err:
				#print("OS error {1}: {0}".format(err,port))
				pass

			except ConnectionRefusedError:
				of = open('log_{0}'.format(publicKey),'a')
				of.write('ConnectionRefusedError {0}\n'.format(port))
				of.close()

	def requestNei(dic_network_node,list_network_node,publicKey):


		while True:
			index = random.randint(0,len(list_network_node)-1)
			if index == list_network_node.index(publicKey):
				
				#print ('SHIT!')
				pass
			else:
				break
		##print (index,list_network_node[index],dic_network_node[list_network_node[index]][0])
		publicKey_node = dic_network_node[list_network_node[index]][0]
		host_node = dic_network_node[list_network_node[index]][1]
		port_node = int(dic_network_node[list_network_node[index]][2])

		msg = {'object':'node',
			   'hashKey':str(publicKey),
			   'action':'request_Nei',
			   'data':dic_network_node[publicKey]}
		msg = (json.dumps(msg)+'\n').encode()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((host_node,port_node))
			s.send(msg)
			data = ''
			while True:
				tmp = s.recv(4096).decode()
				if tmp[-2:] == '}\n':
					data +=tmp
					break
				else:
					data += tmp
			if data:
				data = json.loads(data)
				#print(data)
				if data['data'] == 'Yes':

					b = [1,list_network_node[index],host_node,port_node,publicKey_node]
				#print (b)

					return b
				elif data['data'] == 'No':
					c = [0,list_network_node[index],host_node,port_node,publicKey_node]
					return c
			else:
				s.close()

		except  OSError as err:
			#print("OS error {1}: {0}".format(err,port_node))
			pass

		except ConnectionRefusedError:
			of = open('log_{0}'.format(publicKey),'a')
			of.write('ConnectionRefusedError {0}\n'.format(port_node))
			of.close()
		



	def neighbour(conn,info, publicKey,list_neighbours):

		if len(list_neighbours) < MAX_NEIGHBORS:
			msg_send = {'object':'node',
				   'hashKey':publicKey,
				   'action':'request_Nei',
				   'data':'Yes'}
			msg_send = (json.dumps(msg_send)+'\n').encode()
			conn.send(msg_send)
			return 1

		else:
			msg_send = {'object':'node',
					   	'hashKey':publicKey,
					    'action':'request_Nei',
					    'data':'No'}
			msg_send = (json.dumps(msg_send)+'\n').encode()
			conn.send(msg_send)
			return 0 