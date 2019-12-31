#	toyssl - Python toy SSL implementation
#	Copyright (C) 2015-2019 Johannes Bauer
#
#	This file is part of toyssl.
#
#	toyssl is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	toyssl is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with toyssl; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import collections
import hashlib
import time
import socket
from ActionBase import ActionBase
from toyssl import SSLConnection
from toyssl.msg.handshake.HelloExtension import HelloExtensionSignatureAlgs, BaseHelloExtension
from toyssl.msg.handshake import ClientHelloPkt
from toyssl.msg.Enums import SSLVersion, CipherSuite, CompressionMethod, SignatureAlgorithm, HashAlgorithm, ExtensionType, HandshakeType
from toyssl.msg.MsgBuffer import MsgBuffer
from toyssl.msg import Protocol
from toyssl.msg import CipherSuiteDirectory
from toyssl.x509 import X509Certificate
from toyssl.log.ExplainedStep import ExplainedSteps, ExplainedValueStep

class ClientHandler(object):
	def __init__(self, conn, logger):
		self._conn = conn
		self._log = logger
		self._msgs = {
			"client": collections.defaultdict(list),
			"server": collections.defaultdict(list),
		}

	def initiate_handshake(self):
		#chello = ClientHelloPkt(SSLVersion.ProtocolTLSv1_2)
		chello = ClientHelloPkt(SSLVersion.ProtocolSSLv3_0)
		#csdir = CipherSuiteDirectory().kwfilter(sig_alg = "RSA", kex_alg = "DHE", kex_pfs = True, cipher_name = "AES", cipher_keylen = 128)
		csdir = CipherSuiteDirectory().kwfilter(sig_alg = "RSA", kex_alg = "DH", kex_pfs = True, cipher_name = "AES", cipher_keylen = 128, cipher_opmode = "CBC")
		for cs in csdir:
			self._log.debug("Adding cipher suite: 0x%x = %s" % (int(cs.csid), cs.csid.name))
			chello.add_cipher_suite(cs.csid)
		#chello.add_cipher_suite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA)
		#chello.add_cipher_suite(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384)
		chello.add_compression_method(CompressionMethod.null)
		chello.add_extension(HelloExtensionSignatureAlgs().add_algorithm(SignatureAlgorithm.ECDSA, HashAlgorithm.sha256))
		chello.add_extension(BaseHelloExtension(ExtensionType.heartbeat, MsgBuffer(b"\x01")))
		self._conn.send_pkt(chello)

		self._crandom = chello.random

	def tx_packet(self, layered_pkt):
		self._msgs["client"][layered_pkt.application.packet_type()].append(layered_pkt.application)
		self._log.debug("-> %s" % (str(layered_pkt.application)))

	def rx_packet(self, layered_pkt):
		self._msgs["server"][layered_pkt.application.packet_type()].append(layered_pkt.application)
		pkt = layered_pkt.application
		ptype = pkt.packet_type()
		self._log.debug("<- %s" % (str(layered_pkt.application)))

		if ptype is HandshakeType.ServerHello:
			self._srandom = pkt.random
		elif ptype is HandshakeType.ServerKeyExchange:
			server_cert_der = self._msgs["server"][HandshakeType.Certificate][0].get_cert(0)
			server_cert = X509Certificate.fromderobj(server_cert_der)

			signed_kex_params = MsgBuffer()
			signed_kex_params += self._msgs["client"][HandshakeType.ClientHello][0].random
			signed_kex_params += self._msgs["server"][HandshakeType.ServerHello][0].random
			signed_kex_params += pkt.get_signedpayload()

			explanation = ExplainedSteps("Verification of ServerKeyExchange parameters")
			explanation.append(ExplainedValueStep("Signed KEX parameters", signed_kex_params))
			sig_valid = server_cert.publickey.verify_md5sha1(signed_kex_params.data, pkt.signature.data, explain = explanation)
			self._conn.explain(explanation)

			if not sig_valid:
				raise Exception("Signature check failed for KEX parameters.")
		elif ptype is HandshakeType.ServerHelloDone:
			print("TODO")



class ActionClient(ActionBase):
	def run(self):
		proto = Protocol()
		connection = SSLConnection(proto)
		handler = ClientHandler(connection, self._log)
		connection.set_handler(handler)
		socket_conn = socket.create_connection((self._args.host, self._args.port), timeout = 0.5)
		connection.set_peer_socket(socket_conn)
		handler.initiate_handshake()

		time.sleep(1)
		print("WRITING LOG")
		connection.log.writelog("client.html")
