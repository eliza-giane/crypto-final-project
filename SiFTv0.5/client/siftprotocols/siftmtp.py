#python3

import socket
import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Util import Padding
from Crypto import Random

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.msg_hdr_rsv = b'\x00\x00'

		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_mac = 12
		self.size_etk = 256

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
		self.snd_sqn = 0
		self.rcv_sqn = 0
		self.transfer_key = None

	def set_transfer_key(self, key):
		print('\ntransfer key was:', self.transfer_key)
		print("\nI SET IT HEREEEEE", key)
		self.transfer_key = key #random generated (in login)
		print("\nself transfer key is: ", self.transfer_key)
		

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		#process this normally
		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv]
		
		return parsed_msg_hdr
	
	# receives n bytes from the peer socket
	def receive_bytes(self, n):

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
		print("\nRECEIVING MESSAGE")

		self.rcv_sqn += 1
		try:
			# GETS UNPARSED MESSAGE HEADER
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		# GETS PARSED HEADER
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		# GETS MESSAGE LENGTH
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder="big")
		if msg_sqn < self.rcv_sqn:
			raise SiFT_MTP_Error('Old sequence number')

		if parsed_msg_hdr['typ'] == self.type_login_req: 
			print("\nRECEIVING A RESPONSE")

			try:
				#GETS MESSAGE BODY
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_mac - self.size_etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
			
			# GETS MAC
			try:
				msg_mac = self.receive_bytes(self.size_mac)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message MAC --> ' + e.err_msg)

			if len(msg_body) != msg_len - self.size_msg_hdr - self.size_mac - self.size_etk: 
				raise SiFT_MTP_Error('Incomplete message body received')
			
			try:
				msg_etk = self.receive_bytes(self.size_etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message ETK --> ' + e.err_msg)

			pubkey = ''
			pivkey = ''
			pubkeyfile = './pubkey'
			pivkeyfile = './pivkey'
			with open(pubkeyfile, 'rb') as f:
				pubkeystr = f.read()
			try:
				pubkey = RSA.import_key(pubkeystr)
			except ValueError:
				print('Error: Cannot import public key from file ' + pubkeyfile)
				sys.exit(1)
			
			with open(pivkeyfile, 'rb') as f:
				pivkeystr = f.read()
			try:
				pivkey = RSA.import_key(pivkeystr)
			except ValueError:
				print('Error: Cannot import private key from file ' + pivkeyfile)
				sys.exit(1)

			RSAcipher = PKCS1_OAEP.new(pivkey)
			self.set_transfer_key(RSAcipher.decrypt(msg_etk)) 

			# DEBUG 
			if self.DEBUG:
				print('MTP message received (' + str(msg_len) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_body)) + '): ' + msg_body.hex())
				print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
				print('ETK (' + str(len(msg_etk)) + '): ' + msg_etk.hex())
				print('------------------------------------------')
			# DEBUG  
			
		else:
			print("\nRECEIVING ELSE")
			try:
				#GETS MESSAGE BODY
				msg_body = self.receive_bytes(msg_len - self.size_msg_hdr - self.size_mac)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
			
			# GETS MAC
			try:
				msg_mac = self.receive_bytes(self.size_mac)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to receive message MAC --> ' + e.err_msg)

			# DEBUG 
			if self.DEBUG:
				print('MTP message received (' + str(msg_len) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('BDY (' + str(len(msg_body)) + '): ' + msg_body.hex())
				print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
				print('------------------------------------------')
			# DEBUG #

		# self.set_transfer_key(RSAcipher.decrypt(msg_etk)) 
		# print("\nNEW EDIT TRANSFER KEY: ", self.transfer_key)
		msg_hdr_sqn = (self.rcv_sqn).to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
		nonce = msg_hdr_sqn + msg_hdr_rnd    # parsed_msg_hdr['sqn'] +  parsed_msg_hdr['rnd']
		print("Transfer key: ", self.transfer_key)
		print("Message type: ", parsed_msg_hdr['typ'])
		cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
		cipher.update(msg_hdr)
		
		try:
			# GETS THE PAYLOAD 
			payload = cipher.decrypt_and_verify(msg_body, msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Error: Operation Failed!')

		return parsed_msg_hdr['typ'], payload

	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		print("\nSENDING MESSAGE")

		self.snd_sqn += 1 
		self.set_transfer_key(Random.get_random_bytes(32)) #generates fresh 32 byte random temporary key
		
		if msg_type == self.type_login_req: # includes etk portion
			print("\nSENDING A REQUEST")

			if not self.transfer_key:
				raise SiFT_MTP_Error("Transfer key has not been established")

			# build message
			msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
			msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

			### us:
			msg_hdr_sqn = (self.snd_sqn).to_bytes(self.size_msg_hdr_sqn, byteorder='big') #increments the sequence
			msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
			msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + self.msg_hdr_rsv
			nonce = msg_hdr_sqn + msg_hdr_rnd
			cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
			cipher.update(msg_hdr)
			msg_epd, msg_mac = cipher.encrypt_and_digest(msg_payload)

			pubkey = ''
			pubkeyfile = './pubkey'
			
			with open(pubkeyfile, 'rb') as f:
				pubkeystr = f.read()
			try:
				pubkey = RSA.import_key(pubkeystr)
			except ValueError:
				print('Error: Cannot import public key from file ' + pubkeyfile)
				sys.exit(1)
				
			RSAcipher = PKCS1_OAEP.new(pubkey)
			msg_etk = RSAcipher.encrypt(self.transfer_key) 

			# DEBUG 
			if self.DEBUG:
				print('MTP message to send (' + str(msg_size) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('EPD (' + str(len(msg_epd)) + '): ' + msg_epd.hex())
				print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
				print('ETK (' + str(len(msg_etk)) + '): ' + msg_etk.hex())
				# print(msg_payload.hex())
				print('------------------------------------------')
			# DEBUG 

			# try to send
			try:
				self.send_bytes(msg_hdr + msg_epd + msg_mac + msg_etk)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
		
		else: # does not include etk portion
			print("\nSENDING ELSE")
			if not self.transfer_key:
				raise SiFT_MTP_Error("Transfer key has not been established")

			# build message
			msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
			msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

			### us:
			msg_hdr_sqn = (self.snd_sqn).to_bytes(self.size_msg_hdr_sqn, byteorder='big') #increments the sequence
			msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
			msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + self.msg_hdr_rsv
			nonce = msg_hdr_sqn + msg_hdr_rnd
			cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_mac)
			cipher.update(msg_hdr)
			msg_epd, msg_mac = cipher.encrypt_and_digest(msg_payload)

			# DEBUG 
			if self.DEBUG:
				print('MTP message to send (' + str(msg_size) + '):')
				print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
				print('EPD (' + str(len(msg_epd)) + '): ' + msg_epd.hex())
				print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
				print('------------------------------------------')
			# DEBUG 

			# try to send
			try:
				self.send_bytes(msg_hdr + msg_epd + msg_mac)
			except SiFT_MTP_Error as e:
				raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)