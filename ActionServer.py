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

import time
import socket
import collections
from ActionBase import ActionBase
from toyssl.msg import Protocol
from toyssl.msg.MsgBuffer import MsgBuffer
from toyssl import SSLConnection
from toyssl.msg.handshake import ServerHelloPkt, CertificatePkt, ServerKeyExchangePkt, ServerHelloDonePkt
from toyssl.msg.Enums import SSLVersion, CipherSuite, CompressionMethod, SignatureAlgorithm, HashAlgorithm, ExtensionType, HandshakeType, KeyExchangeAlgorithm, ChangeCipherSpecType
from toyssl.x509.PEMEncoder import pem_readfile
from toyssl.crypto.KexParams import DHModPKexParams
from toyssl.x509.PrivateKey import PrivateKey
from toyssl.crypto.PreMasterSecret import PreMasterSecret
from toyssl.crypto.Enums import PMSCalcLabel, PMSPRF
from toyssl.log.ExplainedStep import ExplainedSteps, ExplainedValueStep

class ServerHandler(object):
	def __init__(self, conn, logger):
		self._conn = conn
		self._log = logger
		self._msgs = {
			"client": collections.defaultdict(list),
			"server": collections.defaultdict(list),
		}

	def tx_packet(self, layered_pkt):
		self._msgs["server"][layered_pkt.application.packet_type()].append(layered_pkt.application)
		self._log.debug("-> %s" % (str(layered_pkt.application)))

	def rx_packet(self, layered_pkt):
		self._msgs["client"][layered_pkt.application.packet_type()].append(layered_pkt.application)
		self._log.debug("<- %s" % (str(layered_pkt.application)))
		pkt = layered_pkt.application

		if layered_pkt.application.packet_type() is HandshakeType.ClientHello:
			# Issue a server hello as a response
			rsp = ServerHelloPkt(SSLVersion.ProtocolTLSv1_0)
			rsp.set_compression_method(CompressionMethod.null)
			rsp.set_cipher_suite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
			self._conn.send_pkt(rsp)

			# Then send the server certificate
			server_cert = pem_readfile("server.crt", "CERTIFICATE")
			rsp = CertificatePkt()
			rsp.add_cert(server_cert)
			self._conn.send_pkt(rsp)

			# Then prepare the server key exchange
			explanation = ExplainedSteps("Server key exchange")
			dh_params = pem_readfile("dhp.pem", "DH PARAMETERS")
			kex_params = DHModPKexParams.parse(dh_params)
			rsp = ServerKeyExchangePkt(KeyExchangeAlgorithm.DHE_RSA)
			rsp.set_kex_params(kex_params)
			rsp.set_kex_session(kex_params.new_session().randomize())

			# Sign the server key exchange message
			signed_kex_params = MsgBuffer()
			signed_kex_params += self._msgs["client"][HandshakeType.ClientHello][0].random
			signed_kex_params += self._msgs["server"][HandshakeType.ServerHello][0].random
			signed_kex_params += rsp.get_signedpayload()
			signed_kex_params.hexdump()
			priv_key = PrivateKey.from_der(pem_readfile("server.key", "PRIVATE KEY"))
			signature = priv_key.sign_md5sha1(signed_kex_params.data)
			rsp.set_signature(signature)

			# Explain it first
			self._conn.explain(explanation)

			# And send it to the client
			self._conn.send_pkt(rsp)

			# Then send the ServerHelloDone
			rsp = ServerHelloDonePkt()
			self._conn.send_pkt(rsp)

		elif layered_pkt.application.packet_type() is ChangeCipherSpecType.ChangeCipherSpec:
			explanation = ExplainedSteps("Key agreement")
			ske = self._msgs["server"][HandshakeType.ServerKeyExchange][0]
			cke = self._msgs["client"][HandshakeType.ClientKeyExchange][0]
			session = ske.kexsession
			shared_secret = session.establish(cke.kexparam)


			server_rnd = self._msgs["server"][HandshakeType.ServerHello][0].random.data
			client_rnd = self._msgs["client"][HandshakeType.ClientHello][0].random.data

			premaster_secret_part1 = shared_secret[:64]
			master_secret_part1 = PreMasterSecret.pms_to_ms(PMSPRF.MD5, PMSCalcLabel.MasterSecret, premaster_secret_part1, server_rnd, client_rnd, explain = explanation)

			premaster_secret_part2 = shared_secret[64:]
			master_secret_part2 = PreMasterSecret.pms_to_ms(PMSPRF.SHA1, PMSCalcLabel.MasterSecret, premaster_secret_part2, server_rnd, client_rnd, explain = explanation)

			master_secret = MsgBuffer(master_secret_part1) ^ MsgBuffer(master_secret_part2)
			master_secret.hexdump()

			self._conn.explain(explanation)

class ActionServer(ActionBase):
	def run(self):
		proto = Protocol()
		connection = SSLConnection(proto)
		handler = ServerHandler(connection, self._log)
		connection.set_handler(handler)

		base = socket.socket()
		for port in range(9000, 9999):
			try:
				base.bind(("127.0.0.1", port))
			except OSError:
				continue
			break
		print("Listening port: %d" % (port))
		base.listen(1)
		(socket_conn, peer) = base.accept()

		connection.set_peer_socket(socket_conn)

		time.sleep(1)
		print("WRITING LOG")
		connection.log.writelog("server.html")



