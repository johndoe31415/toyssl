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

import re
import pprint

from toyssl.utils import Comparable

class OID(Comparable):
	def __init__(self, oidstr):
		self._oid = tuple(int(v) for v in oidstr.split("."))

	@property
	def value(self):
		return self._oid

	@staticmethod
	def cmpadapt(other):
		if isinstance(other, str):
			return OID(other)
		return other

	@property
	def cmpkey(self):
		return self.value

	@property
	def numstr(self):
		return ".".join(str(v) for v in self.value)

	def __str__(self):
		return "OID<%s>" % (self.numstr)

class OIDDB(object):
	_ELEMENT_RE = re.compile(r"(?P<name>[-A-Za-z0-9]+)\((?P<id>\d+)\)")
	def __init__(self):
		self._db = (None, { })

	def _get_element(self, element):
		result = self._db
		for (sid, name) in element:
			result = result[1][sid]
		return result

	def _add_element(self, element):
		(add_sid, add_name) = element[-1]
		base = self._get_element(element[:-1])
		if add_sid not in base[1]:
			base[1][add_sid] = [ add_name, { } ]
		else:
			cur_name = base[1][add_sid][0]
			if (cur_name is not None) and (add_name is not None) and (cur_name != add_name):
				oid = ".".join(str(value[0]) for value in element)
				new_id = ".".join(str(value[1] or value[0]) for value in element)
				raise Exception("Conflicting name for OID %s: %s given, but \"%s\" already in DB for this OID" % (oid, new_id, cur_name))
			elif (cur_name is None) and (add_name is not None):
				base[1][add_sid][0] = add_name

	def _add_all_elements(self, elements):
		for i in range(len(elements)):
			self._add_element(elements[:1 + i])

	def parseline(self, line):
		elements = line.split()
		parsed_element = [ ]

		for element in elements:
			if element.isnumeric():
				sid = int(element)
				name = None
			else:
				result = self._ELEMENT_RE.match(element)
				if result is None:
					raise Exception("Error: cannot parse '%s'." % (element))
				result = result.groupdict()
				sid = int(result["id"])
				name = result["name"]
			parsed_element.append((sid, name))
		self._add_all_elements(parsed_element)

	def loadfromtextfile(self, textfilename):
		f = open(textfilename)
		for line in f:
			line = line.rstrip("\r\n")
			if line.startswith("#"):
				continue
			self.parseline(line)
		f.close()
		return self

	def dump(self):
		pprinter = pprint.PrettyPrinter()
		pprinter.pprint(self._db)

	def resolve(self, oid):
		assert(isinstance(oid, OID))
		node = self._db
		text = ""
		for element in oid.value:
			if (node is not None) and (element in node[1]):
				if node[1][element][0] is None:
					text += ".%d" % (element)
				else:
					text += "." + node[1][element][0]
				node = node[1][element]
			else:
				node = None
				text += ".%d" % (element)
		return text[1:]

