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

import unittest

from toyssl.msg.MsgBuffer import MsgBuffer

class OpaqueTest(unittest.TestCase):
	def test_simple(self):
		buf = MsgBuffer(bytes.fromhex("05 aabbccddee 03 112233 02 0815"))
#		with buf.new_marker("integers"):
		with buf.new_marker("a") as marker:
			value = int(buf.get_opaque(1))
			marker.add_comment("0x%x" % (value))
			self.assertEqual(value, 0xaabbccddee)
		with buf.new_marker("b") as marker:
			value = int(buf.get_opaque(1))
			marker.add_comment("0x%x" % (value))
			self.assertEqual(value, 0x112233)
		with buf.new_marker("c") as marker:
			value = int(buf.get_opaque(1))
			marker.add_comment("0x%x" % (value))
			self.assertEqual(value, 0x0815)
		self.assertEqual([ marker.depth for marker in buf.markers ], [ 0, 1, 2, 2, 1, 2, 2, 1, 2, 2 ])
	
	def test_nesting(self):
		buf = MsgBuffer(bytes.fromhex("05 aabbccddee 03 112233 02 0815"))
		with buf.new_marker("integers"):
			with buf.new_marker("a") as marker:
				value = int(buf.get_opaque(1))
				marker.add_comment("0x%x" % (value))
				self.assertEqual(value, 0xaabbccddee)
			with buf.new_marker("b") as marker:
				value = int(buf.get_opaque(1))
				marker.add_comment("0x%x" % (value))
				self.assertEqual(value, 0x112233)
			with buf.new_marker("c") as marker:
				value = int(buf.get_opaque(1))
				marker.add_comment("0x%x" % (value))
				self.assertEqual(value, 0x0815)
		self.assertEqual([ marker.depth for marker in buf.markers ], [ 0, 1, 2, 3, 3, 2, 3, 3, 2, 3, 3 ])
	
	def test_concat(self):
		sub_buf = MsgBuffer()
		with sub_buf.new_marker("IntA"):
			sub_buf.add_opaque(1, b"ABC")
		with sub_buf.new_marker("IntB"):
			sub_buf.add_opaque(1, b"DEF")

		buf = MsgBuffer()
		with buf.new_marker("X"):
			buf.add_opaque(1, sub_buf)
		with buf.new_marker("Y"):
			buf.add_opaque(1, sub_buf)

		buf.markers.dump()
		

