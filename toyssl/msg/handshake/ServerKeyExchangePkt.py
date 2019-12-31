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

class ServerKeyExchangePkt(HandshakePkt):
	def __init__(self, kexalgorithm):
		self._kexalgorithm = kexalgorithm
		self._kexparams = None
		self._kexsession = None
		self._signature = None
		self._signedpayload = None
		assert(isinstance(self._kexalgorithm, KeyExchangeAlgorithm))

	@staticmethod
	def packet_type():
		return HandshakeType.ServerKeyExchange

	@property
	def kexalgorithm(self):
		return self._kexalgorithm
	
	@property
	def kexparams(self):
		return self._kexparams

	@property
	def signature(self):
		return self._signature

	@property
	def kexsession(self):
		return self._kexsession

	def set_kex_params(self, kexparams):
		self._signedpayload = None
		self._kexparams = kexparams
		return self
	
	def set_kex_session(self, kexsession):
		self._signedpayload = None
		self._kexsession = kexsession
		return self

	def get_signedpayload(self):
		if self._signedpayload is not None:
			return self._signedpayload
		msg = MsgBuffer()
		msg.add_opaque_uint(self._kexparams.p, 2)
		msg.add_opaque_uint(self._kexparams.g, 2)
		msg.add_opaque_uint(self._kexsession.Ys, 2)
		self._signedpayload = msg
		return msg

	def set_signature(self, signature):
		self._signature = signature
		return self

	def serialize(self):
		assert(self._signature is not None)
		msg = MsgBuffer()
		with msg.new_marker("HandshakeType") as marker:
			msg.add_uint8(int(self.packet_type()))
			marker.add_comment(ServerKeyExchangePkt.packet_type().name)
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
			assert(msg.get_uint8() == int(ServerKeyExchangePkt.packet_type()))
			marker.add_comment(ServerKeyExchangePkt.packet_type().name)

		msg = msg.get_opaque(3, name = "Payload")
		pkt = ServerKeyExchangePkt(KeyExchangeAlgorithm.DHE_RSA)

		start_payload = None
		with msg.new_marker("ServerDHParams"):
			p = int(msg.get_opaque(2, name = "p"))
			g = int(msg.get_opaque(2, name = "g"))
			Ys = int(msg.get_opaque(2, name = "Ys"))
			pkt._signedpayload = msg.get_abs_buffer(start_payload, msg.pos)
			pkt._kexparams = DHModPKexParams(p, g)
			pkt._kexsession = pkt._kexparams.new_session().setYs(Ys)

		pkt._signature = msg.get_opaque(2, name = "Signature")
		return pkt

	def __str__(self):
		return "ServerKeyExchangePkt<%s: %s / %s>" % (self.kexalgorithm, str(self.kexparams), str(self.kexsession))


