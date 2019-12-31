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

from ..Enums import SSLVersion, CipherSuite, CompressionMethod, ExtensionType, HandshakeType
from ..MsgBuffer import MsgBuffer
from toyssl.crypto.Random import secure_rand
from .HelloExtension import BaseHelloExtension
from toyssl.hexdump import hex2printstr
from .HandshakePkt import HandshakePkt

class ServerHelloPkt(HandshakePkt):
	def __init__(self, proto_version):
		self._proto_version = proto_version
		self._random_time = int(time.time())
		self._random_data = secure_rand(28)
		self._sessionid = secure_rand(32)
		self._cipher_suite = None
		self._compression_method = None
		self._extensions = [ ]
		assert(isinstance(self._proto_version, SSLVersion))

	@staticmethod
	def packet_type():
		return HandshakeType.ServerHello

	@property
	def random(self):
		msg = MsgBuffer()
		msg.add_uint32(self._random_time)
		msg += self._random_data
		return msg

	def set_cipher_suite(self, cipher_suite):
		assert(isinstance(cipher_suite, CipherSuite))
		self._cipher_suite = cipher_suite
		return self

	def set_compression_method(self, compression_method):
		assert(isinstance(compression_method, CompressionMethod))
		self._compression_method = compression_method
		return self

	def add_extension(self, extension):
		assert(isinstance(extension, BaseHelloExtension))
		self._extensions.append(extension)
		return self

	def serialize(self):
		assert(self._cipher_suite is not None)
		assert(self._compression_method is not None)
		msg = MsgBuffer()
		with msg.new_marker("HandshakeType") as marker:
			msg.add_uint8(int(self.packet_type()))
			marker.add_comment(ServerHelloPkt.packet_type().name)

		with msg.add_opaque_deferred(3):
			msg.add_uint16(int(self._proto_version))
			msg.add_uint32(self._random_time)
			msg += self._random_data
			if self._sessionid is not None:
				msg.add_opaque(1, self._sessionid)
			else:
				msg.add_uint8(0)
			
			msg.add_uint16(int(self._cipher_suite))
			msg.add_uint8(int(self._compression_method))

		return msg

	@staticmethod
	def parse(msg):
		assert(isinstance(msg, MsgBuffer))
		msg.seek(0)
		with msg.new_marker("HandshakeType") as marker:
			assert(msg.get_uint8() == int(ServerHelloPkt.packet_type()))
			marker.add_comment(ServerHelloPkt.packet_type().name)
		msg = msg.get_opaque(3, name = "Payload")

		with msg.new_marker("ProtocolVersion") as marker:
			proto_version = SSLVersion(msg.get_uint16())
			marker.add_comment(proto_version.name)
		pkt = ServerHelloPkt(proto_version)
		with msg.new_marker("Random"):
			with msg.new_marker("Time"):
				pkt._random_time = msg.get_uint32()
			with msg.new_marker("Other"):
				pkt._random_data = msg.get_buffer(28)
		with msg.new_marker("Session"):
			pkt._sessionid = msg.get_opaque(1).data

		with msg.new_marker("CipherSuite") as marker:
			csid = msg.get_uint16()
			pkt._cipher_suite = CipherSuite(csid)
			marker.add_comment(pkt._cipher_suite.name)

		with msg.new_marker("CompressionMethod") as marker:
			compid = msg.get_uint8()
			pkt._compression_method = CompressionMethod(compid)
			marker.add_comment(pkt._compression_method.name)

		if msg.remaining > 0:
			with msg.new_marker("Extensions"):
				# Extension decoding
				ext_count = 0
				ext_length = msg.get_uint16()
				assert(ext_length == msg.remaining)
				while msg.remaining > 0:
					extname = "Extension%d" % (ext_count)
					with msg.new_marker(extname):
						with msg.new_marker("Type") as marker:
							extension_type = ExtensionType(msg.get_uint16())
							marker.add_comment(str(extension_type))
						with msg.new_marker("Data"):
							extension_data = msg.get_opaque(2)
					extension = BaseHelloExtension.parse(extension_type, extension_data)
					pkt.add_extension(extension)
					ext_count += 1
		return pkt

	def __str__(self):
		return "ServerHelloPkt<%s, t = %d, RND = %s, Session = %s, CipherSuite = %s, CompressionMethod = %s, Extensions = %s>" % (self._proto_version, self._random_time, hex2printstr(self._random_data), hex2printstr(self._sessionid), self._cipher_suite, self._compression_method, self._extensions)

