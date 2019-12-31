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

from .DERDecoder import der_decode

class X509BaseExtension(object):
	def __init__(self, oid, data):
		self._oid = oid
		self._data = data

	def __str__(self):
		return "X509BaseExtension<%s = %s>" % (self._oid, self._data)

class X509ExtensionSubjectKeyIdentifier(X509BaseExtension):
	def __init__(self, oid, data):
		X509BaseExtension.__init__(self, oid, data)
		self._keyid = "".join("%02x" % (c) for c in der_decode(data).asOctets())

	def __str__(self):
		return "X509ExtensionSubjectKeyIdentifier<%s>" % (self._keyid)

class X509ExtensionAuthorityKeyIdentifier(X509BaseExtension):
	def __init__(self, oid, data):
		X509BaseExtension.__init__(self, oid, data)
		self._keyid = "".join("%02x" % (c) for c in data)

	def __str__(self):
		return "X509ExtensionAuthorityKeyIdentifier<%s>" % (self._keyid)

class X509Extension(object):
	_KNOWN_OIDS = {
		"2.5.29.14":	X509ExtensionSubjectKeyIdentifier,
		"2.5.29.35":	X509ExtensionAuthorityKeyIdentifier,
#		"2.5.29.19":	X509ExtensionBasicConstraints,
	}

	@staticmethod
	def decode(oid, data):
		if oid in X509Extension._KNOWN_OIDS:
			return X509Extension._KNOWN_OIDS[oid](oid, data)
		else:
			return X509BaseExtension(oid, data)

