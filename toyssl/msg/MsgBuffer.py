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
from toyssl.hexdump import HexDump
from toyssl.msg.MsgMarkers import MarkerNode

class LengthSetterContext(object):
	def __init__(self, msgbuffer, fieldlen):
		self._msgbuffer = msgbuffer
		self._fieldlen = fieldlen
		self._setpos = 0

	def __enter__(self):
		self._setpos = self._msgbuffer.pos
		with self._msgbuffer.new_marker("OpaqueLength%d" % (self._fieldlen * 8)):
			self._msgbuffer.add_uint(0, self._fieldlen)
		self._ctx = self._msgbuffer.new_marker("OpaqueData")
		self._ctx.enter()
		return self

	def __exit__(self, x, y, z):
		self._ctx.exit()
		curpos = self._msgbuffer.pos
		growth = curpos - self._setpos - self._fieldlen
		self._msgbuffer.patch_uint(self._setpos, growth, self._fieldlen)


class MsgBuffer(object):
	def __init__(self, initial_value = None, default_endian = "BE", absoffset = 0, markers = None):
		if initial_value is not None:
			self._buffer = bytearray(initial_value)
		else:
			self._buffer = bytearray()
		self._endian = default_endian
		self._pos = 0
		self._absoffset = absoffset
		if markers is None:
			self._markers = MarkerNode(0, len(self))
		else:
			self._markers = markers

		assert(self._endian == "BE")

	@property
	def markers(self):
		return self._markers

	def cut_head(self, pos):
		head = self._buffer[:pos]
		self._buffer = self._buffer[pos:]
		return (head, self)

	@property
	def data(self):
		return bytes(self._buffer)

	@property
	def tailbuffer(self):
		return bytes(self._buffer[self._pos : ])

	@property
	def pos(self):
		return self._pos

	@property
	def remaining(self):
		return len(self) - self._pos

	def seek(self, pos):
		self._pos = pos

	@staticmethod
	def _mk_uint(endian, bytelen, value):
		assert(bytelen > 0)
		assert(0 <= value < (256 ** bytelen))
		result = bytearray()
		iterator = range(bytelen)
		if endian == "BE":
			iterator = reversed(iterator)
		for i in iterator:
			result.append((value >> (8 * i)) & 0xff)
		return result

	def _add_uint(self, endian, bytelen, value):
		self._buffer += self._mk_uint(endian, bytelen, value)
		self._pos = len(self._buffer)
		return self

	def _get_uint(self, endian, bytelen):
		assert(bytelen > 0)
		assert(self._pos + bytelen <= len(self._buffer))
		iterator = range(bytelen)
		if endian == "BE":
			iterator = reversed(iterator)
		value = sum(self._buffer[self._pos + index] << (8 * value) for (index, value) in enumerate(iterator))
		self._pos += bytelen
		return value

	def patch_uint(self, atpos, value, bytelen):
		uint = self._mk_uint(self._endian, bytelen, value)
		for (index, value) in enumerate(uint):
			self._buffer[atpos + index] = value
		return self

	def add_uint(self, value, bytelen): return self._add_uint(self._endian, bytelen, value)
	def add_uint8(self, value): return self._add_uint(self._endian, 1, value)
	def add_uint16(self, value): return self._add_uint(self._endian, 2, value)
	def add_uint24(self, value): return self._add_uint(self._endian, 3, value)
	def add_uint32(self, value): return self._add_uint(self._endian, 4, value)
	def add_uint16_be(self, value): return self._add_uint("BE", 2, value)
	def add_uint24_be(self, value): return self._add_uint("BE", 3, value)
	def add_uint32_be(self, value): return self._add_uint("BE", 4, value)
	def add_uint16_le(self, value): return self._add_uint("LE", 2, value)
	def add_uint24_le(self, value): return self._add_uint("LE", 3, value)
	def add_uint32_le(self, value): return self._add_uint("LE", 4, value)

	def get_uint(self, bytelen): return self._get_uint(self._endian, bytelen)
	def get_uint8(self): return self._get_uint(self._endian, 1)
	def get_uint16(self): return self._get_uint(self._endian, 2)
	def get_uint24(self): return self._get_uint(self._endian, 3)
	def get_uint32(self): return self._get_uint(self._endian, 4)
	def get_uint16_be(self): return self._get_uint("BE", 2)
	def get_uint24_be(self): return self._get_uint("BE", 3)
	def get_uint32_be(self): return self._get_uint("BE", 4)
	def get_uint16_le(self): return self._get_uint("LE", 2)
	def get_uint24_le(self): return self._get_uint("LE", 3)
	def get_uint32_le(self): return self._get_uint("LE", 4)

	def add_opaque_uint(self, value, bytelen, minlength = 0):
		value_bytelen = (value.bit_length() + 7) // 8
		value_bytelen = max(value_bytelen, minlength)
		self.add_uint(value_bytelen, bytelen)
		self.add_uint(value, value_bytelen)
		return self
	
	def get_abs_buffer(self, start, end):
		return self._buffer[start : end]

	def get_buffer(self, length):
		data = self._buffer[self._pos : self._pos + length]
		self._pos += length
		return data
	
	def get_opaque(self, fieldlen, name = None):
		if name is None:
			with self.new_marker("OpaqueLength%d" % (fieldlen * 8)) as marker:
				length = self.get_uint(fieldlen)
				marker.add_comment("%d bytes of opaque data (0x%x bytes)" % (length, length))
		else:
			length = self.get_uint(fieldlen)
		with self.new_marker(name or "OpaqueData") as marker_parent:
			absoffset = self.pos + self._absoffset
			data = self.get_buffer(length)
			if name is not None:
				marker_parent.add_comment("%d bytes of opaque data (0x%x bytes)" % (length, length))
		child_data = MsgBuffer(data, absoffset = absoffset, markers = marker_parent)
		return child_data

	def add_opaque(self, fieldlen, data):
		with self.new_marker("OpaqueLength%d" % (fieldlen * 8)) as marker:
			self.add_uint(len(data), fieldlen)
			marker.add_comment("%d bytes of opaque data (0x%x bytes)" % (len(data), len(data)))
		with self.new_marker("OpaqueData") as marker_parent:
			self += data
		return self

	def __iadd__(self, data):
		if isinstance(data, MsgBuffer):
			self.markers.join(data.markers, len(self))
			self._buffer += data._buffer
		else:
			self._buffer += data
		self._pos += len(data)
		return self

	def hexdump(self):
		print("Dumping buffer of %d (0x%x) bytes, position 0x%x:" % (len(self), len(self), self.pos))
		HexDump().dump(self.data, markers = { self.pos: ">" })

	def hexstr(self, maxlength = 80):
		if (maxlength > 0) and (len(self) > maxlength):
			# Limit output
			return "".join("%02x" % (c) for c in self._buffer[:maxlength]) + "..."
		else:
			return "".join("%02x" % (c) for c in self._buffer)

	def __int__(self):
		self.seek(0)
		return self._get_uint(self._endian, len(self))

	def __len__(self):
		return len(self._buffer)

	def new_marker(self, markertext):
		"""All data appended in the returned context will be given the label
		'markertext'."""
		return self.markers.new_context(markertext, lambda: self.pos + self._absoffset)

	def add_opaque_deferred(self, fieldlen):
		"""An opaque field will be added with a length field of 'fieldlen'
		bytes. This fieldlen will be set to a placeholder value first and upon
		exiting the context which is returned by this function, it will be set
		to the amount of appended data."""
		return LengthSetterContext(self, fieldlen)

	def __xor__(self, other):
		assert(len(self) == len(other))
		xored = MsgBuffer()
		xored._buffer = bytearray((x ^ y) for (x, y) in zip(self._buffer, other._buffer))
		return xored

	def __iter__(self):
		return iter(self._buffer)

	def __repr__(self):
		return "MsgBuffer<%d>" % (len(self))

	def __str__(self):
		return "MsgBuffer<%d bytes: %s>" % (len(self), self.hexstr(16))



