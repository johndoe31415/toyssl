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
from toyssl.x509.OID import OID, OIDDB

class OIDDBTest(unittest.TestCase):
	def test_oiddb1(self):
		db = OIDDB()
		oid = OID("1.2.3.4.5")
		self.assertEqual(oid.numstr, "1.2.3.4.5")

		self.assertEqual(db.resolve(oid), "1.2.3.4.5")

		db.parseline("moo(2) koo(3) blubb(4)")
		self.assertEqual(db.resolve(oid), "1.2.3.4.5")

		db.parseline("1 2 foo(3) bar(4) 5")
		self.assertEqual(db.resolve(oid), "1.2.foo.bar.5")

		db.parseline("moo(1) koo(2) 3 4 blubby(5)")
		self.assertEqual(db.resolve(oid), "moo.koo.foo.bar.blubby")
