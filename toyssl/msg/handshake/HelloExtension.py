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

from ..Enums import ExtensionType, HashAlgorithm, SignatureAlgorithm, SupportedGroups, ECPointFormats
from ..MsgBuffer import MsgBuffer
from toyssl.hexdump import hex2printstr

class BaseHelloExtension(object):
	_KNOWN_EXTENSIONS = { }

	def __init__(self, extensiontype, msgbuffer = None):
		assert(isinstance(extensiontype, ExtensionType))
		assert((msgbuffer is None) or isinstance(msgbuffer, MsgBuffer))
		self._extensiontype = extensiontype
		self._msgbuffer = msgbuffer

	def parse(extensiontype, msgbuffer):
		if extensiontype in BaseHelloExtension._KNOWN_EXTENSIONS:
			return BaseHelloExtension._KNOWN_EXTENSIONS[extensiontype].parse(extensiontype, msgbuffer)
		else:
			return BaseHelloExtension(extensiontype, msgbuffer)

	def serialize(self):
		return (self._extensiontype, self._msgbuffer)

	def __repr__(self):
		return str(self)

	def __str__(self):
		return "BaseHelloExtension<%s, %s>" % (self._extensiontype, hex2printstr(self._msgbuffer.data))


class HelloExtensionSignatureAlgs(BaseHelloExtension):
	_SignatureAndHashAlgorithm = collections.namedtuple("SignatureAndHashAlgorithm", [ "sig_alg", "hash_alg" ])

	def __init__(self):
		BaseHelloExtension.__init__(self, ExtensionType.signature_algorithms, None)
		self._algs = [ ]

	def add_algorithm(self, sig_alg, hash_alg):
		self._algs.append(self._SignatureAndHashAlgorithm(sig_alg = sig_alg, hash_alg = hash_alg))
		return self

	def serialize(self):
		msg = MsgBuffer()
		msg.add_uint16(2 * len(self._algs))
		for alg in self._algs:
			msg.add_uint8(int(alg.hash_alg))
			msg.add_uint8(int(alg.sig_alg))
		return (ExtensionType.signature_algorithms, msg)

	def parse(extensiontype, data):
		assert(extensiontype == ExtensionType.signature_algorithms)
		assert(isinstance(data, MsgBuffer))
		self = HelloExtensionSignatureAlgs()
		with data.new_marker("Algorithms"):
			algs = data.get_opaque(2)
			while algs.remaining > 0:
				with algs.new_marker("Algorithm") as marker:
					hash_alg = HashAlgorithm(algs.get_uint8())
					sig_alg = SignatureAlgorithm(algs.get_uint8())
					self.add_algorithm(sig_alg, hash_alg)
					marker.add_comment("%s-%s" % (sig_alg.name, hash_alg.name))
		return self

	def __str__(self):
		return "HelloExtensionSignatureAlgs<%s>" % (self._algs)

class HelloExtensionSupportedGroups(BaseHelloExtension):
	def __init__(self):
		BaseHelloExtension.__init__(self, ExtensionType.supported_groups, None)
		self._groups = [ ]

	def add_group(self, group):
		assert(isinstance(group, SupportedGroups))
		self._groups.append(group)
		return self

	def serialize(self):
		raise Exception(NotImplemented)

	def parse(extensiontype, data):
		assert(extensiontype == ExtensionType.supported_groups)
		assert(isinstance(data, MsgBuffer))
		self = HelloExtensionSupportedGroups()
		with data.new_marker("Groups"):
			groups = data.get_opaque(2)
			while groups.remaining > 0:
				with groups.new_marker("Group") as marker:
					group = SupportedGroups(groups.get_uint16())
					self.add_group(group)
					marker.add_comment("%s" % (group.name))
		return self

	def __str__(self):
		return "HelloExtensionSupportedGroups<%s>" % (self._groups)

class HelloExtensionECPointFormats(BaseHelloExtension):
	def __init__(self):
		BaseHelloExtension.__init__(self, ExtensionType.ec_point_formats, None)
		self._formats = [ ]

	def add_format(self, format):
		assert(isinstance(format, ECPointFormats))
		self._formats.append(format)
		return self

	def serialize(self):
		raise Exception(NotImplemented)

	def parse(extensiontype, data):
		assert(extensiontype == ExtensionType.ec_point_formats)
		assert(isinstance(data, MsgBuffer))
		self = HelloExtensionECPointFormats()
		with data.new_marker("PointFormats"):
			formats = data.get_opaque(2)
			while formats.remaining > 0:
				with formats.new_marker("PointFormat") as marker:
					ptformat = ECPointFormats(formats.get_uint8())
					self.add_format(ptformat)
					marker.add_comment("%s" % (ptformat.name))
		return self

	def __str__(self):
		return "HelloExtensionECPointFormats<%s>" % (self._formats)

BaseHelloExtension._KNOWN_EXTENSIONS[ExtensionType.signature_algorithms] = HelloExtensionSignatureAlgs
BaseHelloExtension._KNOWN_EXTENSIONS[ExtensionType.supported_groups] = HelloExtensionSupportedGroups
BaseHelloExtension._KNOWN_EXTENSIONS[ExtensionType.ec_point_formats] = HelloExtensionECPointFormats

