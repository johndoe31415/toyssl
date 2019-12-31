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
import logging

from .MsgBuffer import MsgBuffer
from .RecordLayerPkt import RecordLayerPkt
from .handshake import parse_handshake_pkt, ClientHelloPkt, ServerHelloPkt, CertificatePkt, ServerKeyExchangePkt, ServerHelloDonePkt
from .changecipherspec import parse_changecipherspec_pkt
from .Enums import SSLVersion, ContentType, HandshakeType

_LayeredPacket = collections.namedtuple("LayeredPacket", [ "record", "application", "data" ])

class Protocol(object):
	def __init__(self):
		self._log = logging.getLogger("toyssl")
		self._rx_engine = None
		self._tx_engine = None

	def set_crypto_engine(self, rx_engine, tx_engine):
		self._rx_engine = rx_engine
		self._tx_engine = tx_engine
		return self

	def serialize(self, app_layer):
		#record_layer = RecordLayerPkt(ContentType.Handshake, SSLVersion.ProtocolTLSv1_2, app_layer.reserialize())
		record_layer = RecordLayerPkt(ContentType.Handshake, SSLVersion.ProtocolTLSv1_0, app_layer.reserialize())
		msgbuf = record_layer.serialize()
		layered = _LayeredPacket(record = record_layer, application = app_layer, data = msgbuf)
		return layered

	def parse(self, data):
		assert(isinstance(data, MsgBuffer))
		record_layer = RecordLayerPkt.parse(data)
		self._log.debug("Parsing record layer packet with content type %s from %d bytes buffer" % (str(record_layer.contenttype), len(data)))

		if record_layer.contenttype == ContentType.Handshake:
			app_layer = parse_handshake_pkt(record_layer.payload)
			assert(not isinstance(app_layer, tuple))
		elif record_layer.contenttype == ContentType.ChangeCipherSpec:
			app_layer = parse_changecipherspec_pkt(record_layer.payload)
			assert(not isinstance(app_layer, tuple))
		else:
			self._log.error("Unknown record type packet: %s" % (str(record_layer)))
			raise Exception(NotImplemented)

		layered = _LayeredPacket(record = record_layer, application = app_layer, data = data)
		return layered
