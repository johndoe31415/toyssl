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

import base64
import hashlib

import pyasn1.codec.der.decoder
from .X509ASN1Model import ASN1Certificate
from .DERDecoder import DERAssigner, der_decode, asn1_bitstring_to_bytes
from .ASN1Handler import ASN1Handler, asn1_decode_date
from .PublicKey import PublicKey
from .SubjIssuer import SubjIssuer
from .X509Extension import X509Extension

_x509_v1_assigner = DERAssigner({
	0: ("header", {
		0: "serial",
		1: "signature_alg",
		2: "issuer",
		3: "validity",
		4: "subject",
		5: "public_key",
	}),
	1: "signature_alg",
	2: "signature",
})

_x509_v3_assigner = DERAssigner({
	0: ("header", {
		0: "x509_version",
		1: "serial",
		2: "signature_alg",
		3: "issuer",
		4: "validity",
		5: "subject",
		6: "public_key",
		7: "extensions",
	}),
	1: "signature_alg",
	2: "signature",
})

class _BaseX509Certificate(object):
	def __init__(self, derobj, asn1):
		self._derobj = derobj
		self._asn1 = asn1
		self._derhash = hashlib.sha256(self._derobj).hexdigest()
		(self._decoded, tail) = pyasn1.codec.der.decoder.decode(self._derobj, asn1Spec = ASN1Certificate())
		if len(tail) > 0:
			raise Exception("Trailing data when trying to parse X.509 certificate")

	@property
	def decoded(self):
		return self._decoded

	@property
	def derhash(self):
		return self._derhash

	@property
	def shortderhash(self):
		return self._derhash[:8]

	@property
	def valid_from(self):
		return asn1_decode_date(self._mydecoded["header"]["validity"][0])

	@property
	def valid_to(self):
		return asn1_decode_date(self._mydecoded["header"]["validity"][1])

	@property
	def publickey(self):
		return PublicKey.from_asn1(self._mydecoded["header"]["public_key"])

	@property
	def subject(self):
		return SubjIssuer.from_asn1(self._mydecoded["header"]["subject"])

	@property
	def issuer(self):
		return SubjIssuer.from_asn1(self._mydecoded["header"]["issuer"])

	@property
	def extensions(self):
		return self._mydecoded["header"].get("extensions")

	def decode_extensions(self):
		if self.extensions is not None:
			for extension in self.extensions:
				oid = str(extension[0])
				data = extension[1].asOctets()
				yield X509Extension.decode(oid, data)

	@property
	def key_identifier(self):
		"""Returns the key identifier which is calculated from the actually
		present public key within the certificate, NOT the one possibly present
		in a X.509 extension field."""
		pubkey_bitstring = self._mydecoded["header"]["public_key"][1]
		pubkey_bytes = asn1_bitstring_to_bytes(pubkey_bitstring)
		key_id = hashlib.sha1(pubkey_bytes).hexdigest()
		return key_id

	@property
	def signature_algs(self):
		"""Returns the header and footer signature algorithm fields. They must
		be identical as a requirement of RFC 3280 5.1.2.2"""
		return (self._mydecoded["header"]["signature_alg"], self._mydecoded["signature_alg"])

	def dump_asn1(self):
		ASN1Handler(self._asn1).dump()

	@property
	def signature_alg(self):
		return self._mydecoded["signature_alg"]

class _X509CertificateVersion1(_BaseX509Certificate):
	def __init__(self, derobj, asn1):
		_BaseX509Certificate.__init__(self, derobj, asn1)
		self._mydecoded = _x509_v1_assigner.assign(self._asn1)

	@property
	def version(self):
		return 1

	def __str__(self):
		return "X509CrtVersion1<Subj=[%s], Issuer=[%s], Hash=%s>" % (self.subject, self.issuer, self.shortderhash)

class _X509CertificateVersion3(_BaseX509Certificate):
	def __init__(self, derobj, asn1):
		_BaseX509Certificate.__init__(self, derobj, asn1)
		self._mydecoded = _x509_v3_assigner.assign(self._asn1)

	@property
	def version(self):
		return 3

	def __str__(self):
		return "X509CrtVersion3<Subj=[%s], Issuer=[%s], Hash=%s>" % (self.subject, self.issuer, self.shortderhash)

class X509Certificate(object):
	@staticmethod
	def fromderobj(derobj):
		asn1 = der_decode(derobj)

		if len(asn1[0]) > 6:
			# Version in header field
			version = int(asn1[0][0])
			if version == 2:
				x509 = _X509CertificateVersion3(derobj, asn1)
			else:
				raise Exception(NotImplemented)
		else:
			# Old v1 type (version == 0)
			x509 = _X509CertificateVersion1(derobj, asn1)
		return x509

	@staticmethod
	def frompemobj(pemobj):
		lines = pemobj.split("\n")
		pemdata = None
		for line in lines:
			line = line.rstrip("\r\n")
			if line == "-----BEGIN CERTIFICATE-----":
				pemdata = [ ]
			elif line == "-----END CERTIFICATE-----":
				break
			elif pemdata is not None:
				pemdata.append(line)
		if pemdata is not None:
			data = "".join(pemdata).encode("utf-8")
			data = base64.b64decode(data)
			return X509Certificate.fromderobj(data)
		else:
			raise Exception("Malformed PEM certificate, no data found.")

	@staticmethod
	def frompemfile(filename):
		return X509Certificate.frompemobj(open(filename, "r").read())
