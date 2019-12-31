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

import io
import datetime

from .OID import OID, OIDDB
from .DERDecoder import asn1_bitstring_to_bytes

def asn1_decode_date(dateobj):
	subtype = type(dateobj.subtype()).__name__
	if subtype == "UTCTime":
		time_t = dateobj.asOctets().decode("utf-8")
		ts = datetime.datetime.strptime(time_t, "%y%m%d%H%M%SZ")
		return ts
	elif subtype == "GeneralizedTime":
		time_t = dateobj.asOctets().decode("utf-8")
		ts = datetime.datetime.strptime(time_t, "%Y%m%d%H%M%SZ")
		return ts
	else:
		raise Exception(NotImplemented)

class ASN1PrettyPrinter(object):
	def __init__(self, asn1):
		self._oiddb = OIDDB()
		self._strm = io.StringIO()
		self._indent = 0
		self._dump(asn1)
		self._dumpstr = self._strm.getvalue()

	@property
	def dumpstr(self):
		return self._dumpstr

	def dump(self):
		print(self.dumpstr)

	def _contline(self, line):
		self._strm.write(line)

	def _beginline(self, line):
		spc = "   " * self._indent
		self._strm.write(spc)
		self._strm.write(line)

	def _endline(self):
		self._strm.write("\n")

	def _dump_enumeration(self, element, name, startchar, endchar):
		self._contline("%s %s\n" % (name, startchar))
		for (index, subelement) in enumerate(element):
			pos_name = None
			if getattr(element, "getNameByPosition", None) is not None:
				pos_name = element.getNameByPosition(index)
			if (pos_name is None) or (pos_name == ""):
				pos_name = "%d" % (index)
			self._indent += 1
			self._beginline("%s: " % (pos_name))
			self._dump(subelement)
			self._endline()
			self._indent -= 1
		self._beginline(endchar)

	def _encode_bindata(self, data):
		return "".join("%02x" % (c) for c in data)

	def _dump_data(self, data, name):
		linelen = 32

		self._contline("%s<%d>" % (name, len(data)))
		hexlines = [ ]
		for i in range(0, len(data), linelen):
			subdata = data[i : i + linelen]
			hexlines.append(self._encode_bindata(subdata))
		if len(hexlines) == 0:
			self._contline("empty data")
		elif len(hexlines) == 1:
			self._contline(hexlines[0])
		else:
			self._indent += 1
			for line in hexlines:
				self._endline()
				self._beginline(line)
			self._indent -= 1

	def _get_classname(self, element):
		return type(element.subtype()).__name__

	def _dump_Sequence(self, element):
		self._dump_enumeration(element, self._get_classname(element), "[", "]")

	def _dump_SequenceOf(self, element):
		self._dump_enumeration(element, self._get_classname(element), "[", "]")

	def _dump_Set(self, element):
		self._dump_enumeration(element, self._get_classname(element), "{", "}")

	def _dump_SetOf(self, element):
		self._dump_enumeration(element, self._get_classname(element), "{", "}")

	def _dump_Integer(self, element):
		value = int(element)
		if value < 10000:
			self._contline("%d" % (value))
		else:
			self._contline("0x%x" % (element))

	def _dump_ObjectIdentifier(self, element):
		oid = OID(str(element))
		oidstr = self._oiddb.resolve(oid)
		self._contline(oidstr)

	def _dump_Null(self, element):
		self._contline("NULL")

	def _dump_UTCTime(self, element):
		ts = asn1_decode_date(element)
		self._contline("UTCTime<%s>" % (ts.strftime("%Y-%m-%d %H:%M:%S")))

	def _dump_GeneralizedTime(self, element):
		ts = asn1_decode_date(element)
		self._contline("GeneralizedTime<%s>" % (ts.strftime("%Y-%m-%d %H:%M:%S")))

	def _dump_BitString(self, element):
		data = asn1_bitstring_to_bytes(element)
		self._dump_data(data, "BitString")

	def _dump_OctetString(self, element):
		self._dump_data(element.asOctets(), "OctetString")

	def _dump_Boolean(self, element):
		self._contline(str((bool(element))))

	def _dump_PrintableString(self, element):
		self._contline("p\"%s\"" % (element))

	def _dump_UTF8String(self, element):
		self._contline("u\"%s\"" % (element))

	def _dump_IA5String(self, element):
		self._contline("i\"%s\"" % (element))

	def _dump_TeletexString(self, element):
		self._contline("t\"%s\"" % (element))

	def _dump(self, element):
		if element is None:
			self._dump_Null(element)
			return

		base_element = element
		element_class = type(element.subtype())

		for _ in range(10):
			class_name = element_class.__name__
			handler = "_dump_" + class_name
			handler_fnc = getattr(self, handler, None)
			if handler_fnc is not None:
				break

			# Go one class up
			element_class = element_class.__bases__[0]

		if handler_fnc is None:
			raise Exception("No handler found for element '%s'." % (str(base_element)))

		handler_fnc(element)



