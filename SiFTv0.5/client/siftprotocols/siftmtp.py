#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		# self.msg_hdr_ver = b'\x00\x05'

		#L: version is 1.0
		self.msg_hdr_ver = b'\x01\x00'

		self.size_msg_hdr = 6
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2

		#L:
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket 
		#L: at the beginning there is no key, recommended to set a static key (transferkey= smth that is 32 bytes) 
		self.send_sqn = 0
		self.rcv_sqn = 0
		self.transfer_key = Random.get_random_bytes(32)

	# L: 
	def set_transfer_key(self, key):
		self.transfer_key = key #random generated (in login)

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		#process this normally
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		
		#L: 
		parsed_msg_hdr['len'] = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		
		parsed_msg_hdr['sqn'] = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'] =  msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		
		return parsed_msg_hdr
	
	

	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		#L: doesn't need to be changed
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):
		#
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		#L: check if the sequence number is correct 
		if parsed_msg_hdr['sqn'] != self.send_sqn:
			raise SiFT_MTP_Error("Sequence numbers do not match")
		
		#L:
		etk = msg_body[::256] #takes last 256 bytes of message as etk
		#decrypt this using RSA-OAEP w/ RSA private key to obtain temporary key tk
   
		# L: 
        # decrypt encrypted, temporary with keypair using temporary key
        # decrypt encrypted payload using temporary key:
        #       - verify MAC
        #       - verify user in 0.5
        #       - save client random
        #       - compute login request hash
	
		return parsed_msg_hdr['typ'], msg_body

	#L: don't touch
	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	#L: create a smth for GCM by using a static key and don't forget to use cipher update funciton
	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		### L: 
		if not self.transfer_key:
			raise SiFT_MTP_Error("Transfer key has not been established")

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_
		msg_mac
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

		### us:
		msg_hdr_sqn = (self.snd_sqn+1).to_bytes(self.size_msg_hdr_sqn, byteorder='big') #increments the sequence
		msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd
		nonce = msg_hdr_sqn + msg_hdr_rnd
		cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=msg_hdr_len)
		cipher.update(msg_hdr)
		msg_epd, msg_mac = cipher.encrypt_and_digest(msg_payload)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(msg_epd)) + '): ' + msg_epd.hex())
			print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
			# print('BDY (' + str(len(msg_payload)) + '): ')
			# print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_epd + msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)




