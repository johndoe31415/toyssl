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

from .Enums import ContentType, SSLVersion
from .MsgBuffer import MsgBuffer

class RecordLayerPkt(object):
	def __init__(self, content_type, ssl_version, payload):
		self._content_type = content_type
		self._ssl_version = ssl_version
		self._payload = payload
		assert(isinstance(self._content_type, ContentType))
		assert(isinstance(self._ssl_version, SSLVersion))
		assert(isinstance(payload, MsgBuffer))

	@property
	def contenttype(self):
		return self._content_type

	@property
	def payload(self):
		return self._payload

	def serialize(self):
		msg = MsgBuffer()
		with msg.new_marker("ContentType") as marker:
			msg.add_uint8(int(self._content_type))
			marker.add_comment(self._content_type.name)
		with msg.new_marker("SSLVersion") as marker:
			msg.add_uint16_be(int(self._ssl_version))
			marker.add_comment(self._ssl_version.name)
		with msg.new_marker("RecordPayload"):
			msg.add_opaque(2, self._payload)
		return msg

	def parse(msg):
		assert(isinstance(msg, MsgBuffer))
		with msg.new_marker("ContentType") as marker:
			content_type = ContentType(msg.get_uint8())
			marker.add_comment(content_type.name)

		with msg.new_marker("SSLVersion") as marker:
			ssl_version = SSLVersion(msg.get_uint16())
			marker.add_comment(ssl_version.name)

		with msg.new_marker("RecordPayload"):
			payload = msg.get_opaque(2)
		if msg.remaining != 0:
			raise Exception("Trailing %d bytes of garbage data after decoding of packet." % (msg.remaining))
		return RecordLayerPkt(content_type, ssl_version, payload)

	def __str__(self):
		return "RecordLayer<%s, %s, %d bytes payload>" % (self._content_type, self._ssl_version, len(self._payload))
