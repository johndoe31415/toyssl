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
import random
from toyssl.utils import Comparable

class _Value(Comparable):
	def __init__(self, value):
		self._value = value

	@property
	def value(self):
		return self._value

	@staticmethod
	def cmpadapt(other):
		if isinstance(other, int):
			return _Value(other)
		return other

	@property
	def cmpkey(self):
		return (self._value, )

	def __str__(self):
		return "<%d>" % (self.value)

class ComparableTest(unittest.TestCase):
	def test_cmp1(self):
		a = _Value(100)
		b = _Value(200)
		self.assertTrue(a < b)
		self.assertTrue(a <= b)
		self.assertTrue(a != b)
		self.assertFalse(a > b)
		self.assertFalse(a >= b)
		self.assertFalse(a == b)

		self.assertFalse(b < a)
		self.assertFalse(b <= a)
		self.assertTrue(b != a)
		self.assertTrue(b > a)
		self.assertTrue(b >= a)
		self.assertFalse(b == a)

	def test_sort(self):
		rndvals = [ _Value(random.randint(0, 10000)) for i in range(100) ]
		rndvals.sort()

		intvals = [ value.value for value in rndvals ]
		self.assertEqual(intvals, sorted(intvals))

	def test_set(self):
		myset = set()
		for _ in range(2500):
			myset.add(_Value(random.randint(0, 99)))

		# Probabilistic testcase, failure probability p = 4.482352e-10 (for n = 2500 and m = 100)
		self.assertEqual(len(myset), 100)
		self.assertEqual([y.value for y in sorted([ x for x in myset ])], list(range(100)))

	def test_conv(self):
		a = _Value(100)
		b = 200
		self.assertTrue(a < b)
		self.assertTrue(a <= b)
		self.assertTrue(a != b)
		self.assertFalse(a > b)
		self.assertFalse(a >= b)
		self.assertFalse(a == b)

		self.assertFalse(b < a)
		self.assertFalse(b <= a)
		self.assertTrue(b != a)
		self.assertTrue(b > a)
		self.assertTrue(b >= a)
		self.assertFalse(b == a)
