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

from ..MsgBuffer import MsgBuffer
from ..Enums import HandshakeType
from .HandshakePkt import HandshakePkt

class CertificatePkt(HandshakePkt):
	def __init__(self):
		self._certs = [ ]

	@staticmethod
	def packet_type():
		return HandshakeType.Certificate

	def add_cert(self, derdata):
		assert(isinstance(derdata, bytes))
		self._certs.append(derdata)

	def get_cert(self, index):
		return self._certs[index]

	def serialize(self):
		msg = MsgBuffer()
		with msg.new_marker("HandshakeType") as marker:
			msg.add_uint8(int(self.packet_type()))
			marker.add_comment(CertificatePkt.packet_type().name)

		with msg.add_opaque_deferred(3):
			with msg.add_opaque_deferred(3):
				for cert in self._certs:
					msg.add_opaque(3, cert)

		return msg

	@staticmethod
	def parse(msg):
		assert(isinstance(msg, MsgBuffer))
		
		msg.seek(0)
		with msg.new_marker("HandshakeType") as marker:
			assert(msg.get_uint8() == int(CertificatePkt.packet_type()))
			marker.add_comment(CertificatePkt.packet_type().name)
		msg = msg.get_opaque(3, name = "Payload")

		pkt = CertificatePkt()

		certificates = msg.get_opaque(3, name = "CertificateList")
		certcnt = 0
		while certificates.remaining > 0:
			certificate = certificates.get_opaque(3, name = "Certificate%d" % (certcnt))
			pkt.add_cert(certificate.data)
			certcnt += 1

		return pkt

	def __str__(self):
		return "CertificatePkt<%d certs>" % (len(self._certs))

