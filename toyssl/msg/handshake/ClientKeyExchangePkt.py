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

from ..Enums import KeyExchangeAlgorithm, HandshakeType
from ..MsgBuffer import MsgBuffer
from .HandshakePkt import HandshakePkt
from toyssl.crypto.KexParams import DHModPKexParams

class ClientKeyExchangePkt(HandshakePkt):
	def __init__(self, kexalgorithm):
		self._kexalgorithm = kexalgorithm
		self._kexparam = None
		assert(isinstance(self._kexalgorithm, KeyExchangeAlgorithm))

	@staticmethod
	def packet_type():
		return HandshakeType.ClientKeyExchange

	@property
	def kexparam(self):
		return self._kexparam

	def serialize(self):
		assert(self._signature is not None)
		msg = MsgBuffer()
		with msg.new_marker("HandshakeType") as marker:
			msg.add_uint8(int(self.packet_type()))
			marker.add_comment(ClientKeyExchangePkt.packet_type().name)
		with msg.add_opaque_deferred(3):
			msg += self.get_signedpayload()
			with msg.add_opaque_deferred(2):
				msg += self._signature
		return msg

	@staticmethod
	def parse(msg):
		assert(isinstance(msg, MsgBuffer))
		msg.seek(0)
		with msg.new_marker("HandshakeType") as marker:
			assert(msg.get_uint8() == int(ClientKeyExchangePkt.packet_type()))
			marker.add_comment(ClientKeyExchangePkt.packet_type().name)

		msg = msg.get_opaque(3, name = "Payload")
		pkt = ClientKeyExchangePkt(KeyExchangeAlgorithm.DHE_RSA)

		start_payload = None
		with msg.new_marker("ClientDHParams"):
			Yc = int(msg.get_opaque(2, name = "Yc"))
			pkt._kexparam = Yc

		return pkt

	def __str__(self):
		return "ClientKeyExchangePkt<%s>" % (str(self.kexparam))


