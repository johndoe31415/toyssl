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

class SubjIssuer(object):
	_KNOWN_FIELDS = {
		"2.5.4.3":					"CN",
		"2.5.4.5":					"serialNumber",
		"2.5.4.6":					"C",
		"2.5.4.7":					"L",
		"2.5.4.8":					"ST",
		"2.5.4.9":					"street",
		"2.5.4.10":					"O",
		"2.5.4.11":					"OU",
		"2.5.4.15":					"businessCategory",
		"2.5.4.17":					"postalCode",
		"1.2.840.113549.1.9.1":		"emailAddress",
	}

	def __init__(self, fields):
		self._fields = fields
		self._fieldcnt = collections.Counter()
		for key in self._fields:
			self._fieldcnt[key] += 1
			if key in self._KNOWN_FIELDS:
				self._fieldcnt[self._KNOWN_FIELDS[key]] += 1

	@staticmethod
	def from_asn1(asn1):
		fields = [ ]
		for field in asn1:
			oid = str(field[0][0])
			value = str(field[0][1])
			fields.append((oid, value))
		return SubjIssuer(fields)

	def duplicate_list(self):
		have = set()
		duplicate = set()
		for key in self._fields.keys():
			if key in have:
				duplicate.add(key)
			have.add(key)
		return [ self._KNOWN_FIELDS.get(key, key) for key in duplicate ]

	def getfieldcnt(self, fieldname):
		return self._fieldcnt[fieldname]

	def getunknownfields(self):
		return set(field[0] for field in self._fields) - set(self._KNOWN_FIELDS.keys())

	def __iter__(self):
		for (key, value) in self._fields:
			yield (self._KNOWN_FIELDS.get(key, key), value)

	def __str__(self):
		return ", ".join("%s=%s" % (key, value) for (key, value) in self)
