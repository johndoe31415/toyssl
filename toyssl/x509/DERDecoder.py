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

import pyasn1.codec.der.decoder

class DERAssigner(object):
	def __init__(self, structure):
		self._structure = structure

	def _assign(self, decodeobj, structure):
		result = { }
		for (key, value) in structure.items():
			if isinstance(value, str):
				if key < len(decodeobj):
					result[value] = decodeobj[key]
			else:
				(name, substructure) = value
				result[name] = self._assign(decodeobj[key], substructure)
		return result

	def assign(self, asn1obj):
		result = self._assign(asn1obj, self._structure)
		return result

def asn1_bitstring_to_bytes(element):
	if (len(element) % 8) != 0:
		raise Exception(NotImplemented)
	bytecnt = (len(element) + 7) // 8
	data = bytes(sum((element[(8 * i) + j] << (7 - j)) for j in range(8)) for i in range(bytecnt))
	return data

def der_decode(derobj):
	(data, trailer) = pyasn1.codec.der.decoder.decode(derobj)
	if len(trailer) > 0:
		raise Exception("There were %d trailing bytes in the %d byte long DER encoding." % (len(trailer), len(derobj)))
	return data
