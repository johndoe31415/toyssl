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
import datetime

from ..Enums import SSLVersion, CipherSuite, CompressionMethod, ExtensionType, HandshakeType
from ..MsgBuffer import MsgBuffer
from toyssl.crypto.Random import secure_rand
from .HandshakePkt import HandshakePkt
from .HelloExtension import BaseHelloExtension
from toyssl.hexdump import hex2printstr
from .HandshakePkt import HandshakePkt

class ClientHelloPkt(HandshakePkt):
	def __init__(self, proto_version):
		self._proto_version = proto_version
		self._random_time = int(time.time())
		self._random_data = secure_rand(28)
		self._sessionid = b""
		self._ciphersuites = [ ]
		self._compression_methods = [ ]
		self._extensions = [ ]
		assert(isinstance(self._proto_version, SSLVersion))

	@staticmethod
	def packet_type():
		return HandshakeType.ClientHello

	@property
	def random(self):
		msg = MsgBuffer()
		msg.add_uint32(self._random_time)
		msg += self._random_data
		return msg

	def add_cipher_suite(self, ciphersuite):
		assert(isinstance(ciphersuite, CipherSuite))
		self._ciphersuites.append(ciphersuite)
		return self

	def add_compression_method(self, compression_method):
		assert(isinstance(compression_method, CompressionMethod))
		self._compression_methods.append(compression_method)
		return self

	def add_extension(self, extension):
		assert(isinstance(extension, BaseHelloExtension))
		self._extensions.append(extension)
		return self

	def serialize(self):
		assert(len(self._ciphersuites) > 0)
		assert(len(self._compression_methods) > 0)
		msg = MsgBuffer()
		with msg.new_marker("HandshakeType") as marker:
			msg.add_uint8(int(self.packet_type()))
			marker.add_comment(ClientHelloPkt.packet_type().name)
		with msg.add_opaque_deferred(3):
			with msg.new_marker("ProtocolVersion"):
				msg.add_uint16(int(self._proto_version))

			with msg.new_marker("Random"):
				msg.add_uint32(self._random_time)
				msg += self._random_data
			with msg.new_marker("Session"):
				msg.add_opaque(1, self._sessionid)
			
			with msg.new_marker("CipherSuites"):
				msg.add_uint16(len(self._ciphersuites) * 2)
				for ciphersuite in self._ciphersuites:
					with msg.new_marker("CipherSuite") as marker:
						msg.add_uint16(int(ciphersuite))
						marker.add_comment(ciphersuite.name)
			msg.add_uint8(len(self._compression_methods))
			for compression_method in self._compression_methods:
				msg.add_uint8(int(compression_method))
			if len(self._extensions) > 0:
				with msg.add_opaque_deferred(2):
					for extension in self._extensions:
						(exttype, extdata) = extension.serialize()
						msg.add_uint16(int(exttype))
						msg.add_opaque(2, extdata)
		return msg

	@staticmethod
	def parse(msg):
		assert(isinstance(msg, MsgBuffer))
		msg.seek(0)
		with msg.new_marker("HandshakeType") as marker:
			assert(msg.get_uint8() == int(ClientHelloPkt.packet_type()))
			marker.add_comment(ClientHelloPkt.packet_type().name)

		msg = msg.get_opaque(3, name = "Payload")

		with msg.new_marker("ProtocolVersion"):
			proto_version = SSLVersion(msg.get_uint16())
		pkt = ClientHelloPkt(proto_version)
		with msg.new_marker("Random"):
			with msg.new_marker("Time") as marker:
				pkt._random_time = msg.get_uint32()
				marker.add_comment(datetime.datetime.utcfromtimestamp(pkt._random_time).strftime("%Y-%m-%d %H:%M:%S"))
			with msg.new_marker("Other"):
				pkt._random_data = msg.get_buffer(28)
		pkt._sessionid = msg.get_opaque(1, name = "Session")
		with msg.new_marker("CipherSuites"):
			ciphersuite_data = msg.get_opaque(2)
			while ciphersuite_data.remaining > 0:
				with ciphersuite_data.new_marker("CipherSuite") as marker:
					csid = ciphersuite_data.get_uint16()
					csuite = CipherSuite(csid)
					pkt.add_cipher_suite(csuite)
					marker.add_comment(csuite.name)
		comp_methods = msg.get_opaque(1, "CompressionMethods")
		while comp_methods.remaining > 0:
			with comp_methods.new_marker("CompressionMethod") as marker:
				comp_method = comp_methods.get_uint8()
				method = CompressionMethod(comp_method)
				marker.add_comment(method.name)
				pkt.add_compression_method(method)


		with msg.new_marker("Extensions"):
			# Extension decoding
			ext_count = 0
			extensions = msg.get_opaque(2)
			while extensions.remaining > 0:
				extname = "Extension%d" % (ext_count)
				with extensions.new_marker(extname):
					with extensions.new_marker("Type") as marker:
						extension_type = ExtensionType(extensions.get_uint16())
						marker.add_comment(extension_type.name)
					extension_data = extensions.get_opaque(2)
				extension = BaseHelloExtension.parse(extension_type, extension_data)
				pkt.add_extension(extension)
				ext_count += 1
		return pkt

	def __str__(self):
		return "ClientHelloPkt<%s, t = %d, RND = %s, Session = %s, CipherSuites = %s, CompressionMethods = %s, Extensions = %s>" % (self._proto_version, self._random_time, hex2printstr(self._random_data), hex2printstr(self._sessionid), self._ciphersuites, self._compression_methods, self._extensions)

