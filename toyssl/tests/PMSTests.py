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
from toyssl.crypto.PreMasterSecret import PreMasterSecret
from toyssl.crypto.Enums import PMSPRF, PMSCalcLabel

class PMSTest(unittest.TestCase):
	def test_pms(self):
		pms = bytes.fromhex("00060000000000000006666f6f626172")
		client_rnd = bytes.fromhex("00000000E10ED1504A197AF5F00475AB36BB8B4FF585119A65ED640E905693B4")
		server_rnd = bytes.fromhex("0000000D1924DDFC0A87B4FD09265D812AD969F7A56A6867D8B51D8A3E83AAE1")
		expect_ms = bytes.fromhex("a69bb342349d0074978f9c9b3dc9e5bc1a4d595d7bfd7e2e3b4440d6ac2b9d56a287a94164ae633912515072570e71fb")
		
		calced_ms = PreMasterSecret.pms_to_ms(PMSPRF.SHA256, PMSCalcLabel.MasterSecret, pms, server_rnd, client_rnd)
		self.assertEqual(calced_ms, expect_ms)

