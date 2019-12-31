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

from toyssl.msg.MsgMarkers import MarkerNode

class MarkerTest(unittest.TestCase):
	def test_simple(self):
		markers = MarkerNode(10, 64)

		markers.new_marker(0, 5, "Mark1")
		markers.new_marker(5, 7, "Mark2")
		markers.new_marker(7, 9, "Mark3")
		kiddo = markers.new_marker(9, 64, "Mark4")
		kiddo.new_marker(3, 17, "Kid")

		expect_depths = [ 0, 1, 1, 1, 1, 2 ]
		depths = [ marker.depth for marker in markers ]
		self.assertEqual(depths, expect_depths)
		
		expect_offsets = [ (10, 64), (10 + 0, 10 + 5), (10 + 5, 10 + 7), (10 + 7, 10 + 9), (10 + 9, 10 + 64), (10 + 9 + 3, 10 + 9 + 17) ]
		offsets = [ (marker.startoffset, marker.endoffset) for marker in markers ]
		self.assertEqual(offsets, expect_offsets)
	
	def test_offset(self):
		markers = MarkerNode(0, 58)

		pos = 3
		with markers.new_context("Mark1", lambda: pos):
			pos = 5
		
		with markers.new_context("Mark2", lambda: pos) as kid:
			pos = 12
			
			kidpos = 0
			with kid.new_context("Mark3", lambda: kidpos):
				kidpos = 3
		
		with markers.new_context("Mark4", lambda: pos):
			pos = 14

		expect_depths = [ 0, 1, 1, 2, 1 ]
		depths = [ marker.depth for marker in markers ]
		self.assertEqual(depths, expect_depths)
		
		expect_offsets = [ (0, 58), (3, 5), (5, 12), (5, 8), (12, 14) ]
		offsets = [ (marker.startoffset, marker.endoffset) for marker in markers ]
		self.assertEqual(offsets, expect_offsets)

