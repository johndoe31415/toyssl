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

class MsgBufferTest(unittest.TestCase):
	def test_addint(self):
		buf = MsgBuffer()
		buf.add_uint24_be(123456)
		self.assertEqual(buf.data, b"\x01\xe2\x40")

		buf.add_uint32_be(123456789)
		self.assertEqual(buf.data, b"\x01\xe2\x40\x07\x5b\xcd\x15")

	def test_addbuf(self):
		buf = MsgBuffer()
		buf += b"foobar"
		buf += b"mookoo"
		self.assertEqual(buf.data, b"foobarmookoo")

	def test_emptybuf(self):
		buf = MsgBuffer()
		self.assertEqual(buf.data, b"")

	def test_getint(self):
		buf = MsgBuffer()
		buf.add_uint24(1234567)
		buf.add_uint24(7654321)

		buf.seek(0)
		self.assertEqual(buf.get_uint24(), 1234567)
		self.assertEqual(buf.get_uint24(), 7654321)

	def test_setopaque(self):
		buf = MsgBuffer()
		buf.add_opaque(1, b"foo")
		buf.add_opaque(2, b"bar!")
		buf.add_opaque(3, b"mookoo")
		self.assertEqual(buf.data, b"\x03foo\x00\x04bar!\x00\x00\x06mookoo")

	def test_setmarker(self):
		buf = MsgBuffer(b"\x03foo\x00\x04bar!\x00\x00\x06mookoo")
		with buf.new_marker("0:4:<"):
			self.assertEqual(buf.get_opaque(1).data, b"foo")
		with buf.new_marker("4:10:<"):
			self.assertEqual(buf.get_opaque(2).data, b"bar!")
		with buf.new_marker("10:19:<"):
			self.assertEqual(buf.get_opaque(3).data, b"mookoo")
		for marker in buf.markers:
			if (marker.text is not None) and marker.text.endswith(":<"):
				hints = marker.text.split(":")
				expected_start = int(hints[0])
				expected_end = int(hints[1])
				self.assertEqual(expected_start, marker.startoffset)
				self.assertEqual(expected_end, marker.endoffset)

	def test_getmarker_nested(self):
		buf = MsgBuffer(b"\x00\x0b\x03foo\x06barfoo")
		with buf.new_marker("Outer"):
			sub_buf = buf.get_opaque(2)
			self.assertEqual(sub_buf.data, b"\x03foo\x06barfoo")
			with sub_buf.new_marker("Inner1"):
				subsub_buf = sub_buf.get_opaque(1)
				self.assertEqual(subsub_buf.data, b"foo")
			with sub_buf.new_marker("Inner2"):
				subsub_buf = sub_buf.get_opaque(1)
				self.assertEqual(subsub_buf.data, b"barfoo")

		expect = {
			"Outer":		(0, 13),
			"Inner1":		(2, 6),
			"Inner2":		(6, 13),
		}
		fulfilled = set()

		for marker in buf.markers:
			if expect.get(marker.text) is not None:
				(expected_start, expected_end) = expect[marker.text]
				self.assertEqual(expected_start, marker.startoffset)
				self.assertEqual(expected_end, marker.endoffset)
				fulfilled.add(marker.text)
		self.assertEqual(len(fulfilled), len(expect))

	def test_mkmarker_nested(self):
		buf = MsgBuffer()
		with buf.add_opaque_deferred(2):
			buf.add_uint16(0x1122)
			buf.add_uint32(0xaabbccdd)
			buf.add_uint8(0xff)
			with buf.add_opaque_deferred(3):
				buf.add_uint16(0xaaaa)
				buf.add_uint16(0xbbbb)
				buf.add_uint16(0xcccc)
				buf.add_uint8(0x55)
		self.assertEqual(buf.data, bytes.fromhex("0011 1122 aabbccdd ff 000007  aaaa bbbb cccc 55"))

	def test_mkopaque_annotated(self):
		buf = MsgBuffer()
		with buf.new_marker("MainPayload"), buf.add_opaque_deferred(2):
			with buf.new_marker("AnimalCounts"), buf.add_opaque_deferred(2):
				with buf.new_marker("CowCount"):
					buf.add_uint16(9000)
				with buf.new_marker("SheepCount"):
					buf.add_uint16(4321)
				with buf.new_marker("ChickenCount"):
					buf.add_uint32(12345678)
			with buf.new_marker("VehicleCounts"), buf.add_opaque_deferred(2):
				with buf.new_marker("CarCount"):
					buf.add_uint24(133)
				with buf.new_marker("TrainCount"):
					buf.add_uint24(92)
#		buf.markers.dump()

	def test_decode_nested(self):
		buf = MsgBuffer(b"\x00\x04\x03\xaa\xbb\xcc")
		uints = [ ]
	
		with buf.new_marker("Sub1"):
			sub1 = buf.get_opaque(2)

			with sub1.new_marker("Sub2"):
				sub2 = sub1.get_opaque(1)

				for i in range(3):
					with sub2.new_marker("Value%d" % (i)):
						uints.append(sub2.get_uint8())
		self.assertEqual(uints, [ 0xaa, 0xbb, 0xcc ])

		expect_depths = [ 0, 1, 2, 2, 3, 4, 4, 5, 5, 5 ]
		depths = [ marker.depth for marker in buf.markers ]
		self.assertEqual(depths, expect_depths)

	def test_decode_complex(self):
		buf = MsgBuffer(bytes.fromhex("33 0c 44 0a 55 66 77 06 88   03 aa bb cc   99"))
		#                               0  1  2  3  4  5  6  7  8    9 10 11 12   13    14
		#                                  ^     ^           ^       ^           
		with buf.new_marker("Value_0"):
			buf.get_uint8()

		with buf.new_marker("Sub_1"):
			sub1 = buf.get_opaque(1)
			
			with sub1.new_marker("Value_1"):
				sub1.get_uint8()
			with sub1.new_marker("Sub_2"):
				sub2 = sub1.get_opaque(1)
			
				with sub2.new_marker("Value_A"):
					sub2.get_uint16()
				with sub2.new_marker("Value_B"):
					sub2.get_uint8()
				with sub2.new_marker("Sub_3"):
					sub3 = sub2.get_opaque(1)
				
					with sub3.new_marker("Value_X"):
						sub3.get_uint8()
					
					with sub3.new_marker("Sub_4"):
						sub4 = sub3.get_opaque(1)
					
						with sub4.new_marker("Sub_R"):
							sub4.get_uint8()
						with sub4.new_marker("Sub_S"):
							sub4.get_uint8()
						with sub4.new_marker("Sub_T"):
							sub4.get_uint8()

					with sub3.new_marker("Value_Y"):
						sub3.get_uint8()
		
		expect_depths = [ 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 9, 7 ]
		depths = [ marker.depth for marker in buf.markers ]
		self.assertEqual(depths, expect_depths)

		expect_offsets = [ (0, 14), (0, 1), (1, 14), (1, 2), (2, 14) ]
		expect_offsets += [ (2, 3), (3, 14), (3, 4), (4, 14) ]
		expect_offsets += [ (4, 6), (6, 7), (7, 14), (7, 8), (8, 14) ]
		expect_offsets += [ (8, 9), (9, 13), (9, 10), (10, 13), (10, 11), (11, 12), (12, 13), (13, 14)  ]
		offsets = [ (marker.startoffset, marker.endoffset) for marker in buf.markers ]
		self.assertEqual(offsets, expect_offsets)

	def test_decode_very_simple(self):
		buf = MsgBuffer(bytes.fromhex("03 aa bb cc"))
	
		with buf.new_marker("SubStructure"):
			sub = buf.get_opaque(1)
			with sub.new_marker("ValA"):
				sub.get_uint8()
			with sub.new_marker("ValB"):
				sub.get_uint8()
			with sub.new_marker("ValC"):
				sub.get_uint8()
		
		expect_depths = [ 0, 1, 2, 2, 3, 3, 3 ]
		depths = [ marker.depth for marker in buf.markers ]
		self.assertEqual(depths, expect_depths)

		expect_offsets = [ (0, 4), (0, 4), (0, 1), (1, 4), (1, 2), (2, 3), (3, 4) ]
		offsets = [ (marker.startoffset, marker.endoffset) for marker in buf.markers ]
		self.assertEqual(offsets, expect_offsets)

	def test_decode_seq(self):
		buf = MsgBuffer(bytes.fromhex("03 aaaaaa 03 bbbbbb 03 cccccc"))
		with buf.new_marker("Chunk1"):
			buf.get_opaque(1)
		with buf.new_marker("Chunk2"):
			buf.get_opaque(1)
		with buf.new_marker("Chunk3"):
			buf.get_opaque(1)
	
