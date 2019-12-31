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

import pyasn1.codec.der.encoder
import pyasn1.codec.der.decoder
from toyssl.crypto.Random import secure_rand_int
from toyssl.crypto.BinInt import int2bytes
from pyasn1.type import univ

class DHModPKexSession(object):
	def __init__(self, params):
		self._params = params
		self._r = None
		self._Ys = None
	
	@property
	def params(self):
		return self._params

	@property
	def r(self):
		return self._r

	@property
	def Ys(self):
		return self._Ys

	def randomize(self):
		self._r = secure_rand_int(self._params.p)
		self._Ys = pow(self._params.g, self._r, self._params.p)
		return self

	def setYs(self, Ys):
		self._Ys = Ys
		return self

	def establish(self, Yc, explain = None):
		key = pow(Yc, self.r, self.params.p)

		keydata = int2bytes(key)
		return keydata

	def __str__(self):
		if self._r is None:
			return "DHModPKexSession<Ys = 0x%x>" % (self.Ys)
		else:
			return "DHModPKexSession<r = 0x%x, Ys = 0x%x>" % (self.r, self.Ys)

class DHModPKexParams(object):
	def __init__(self, p, g):
		assert(isinstance(p, int))
		assert(isinstance(g, int))
		self._p = p
		self._g = g

	def new_session(self):
		return DHModPKexSession(self)

	@property
	def p(self):
		return self._p
	
	@property
	def g(self):
		return self._g

	@property
	def bytelen(self):
		return (self.p.bit_length() + 7) // 8

	def serialize(self):
		asn1 = univ.Sequence()
		asn1.setComponentByPosition(0, univ.Integer(self.p))
		asn1.setComponentByPosition(1, univ.Integer(self.g))
		return pyasn1.codec.der.encoder.encode(asn1)

	@staticmethod
	def parse(derdata):
		(dhdata, tail) = pyasn1.codec.der.decoder.decode(derdata)
		assert(len(tail) == 0)
		return DHModPKexParams(int(dhdata[0]), int(dhdata[1]))
	
	def __str__(self):
		return "DHModPKexParams<%d bit, p = 0x%x, g = 0x%x>" % (self.p.bit_length(), self.p, self.g)
