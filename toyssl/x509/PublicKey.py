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

import hashlib
from toyssl.crypto.BinInt import int2bytes, bytes2int, unpad_pkcs1
from toyssl.log.ExplainedStep import ExplainedSteps, ExplainedValueStep, ExplainedModularExponentiationStep
from .DERDecoder import der_decode, asn1_bitstring_to_bytes

class _BasePublicKey(object):
	def __init__(self):
		pass

	@property
	def keytype(self):
		raise Exception(NotImplemented)

def _bytes2int(data):
	return sum(value << (8 * index) for (index, value) in enumerate(reversed(data)))

class _ECCPublicKey(_BasePublicKey):
	def __init__(self, curveid, encoded_pubkey):
		_BasePublicKey.__init__(self)
		self._curveid = curveid
		if encoded_pubkey[0] == 0x04:
			coordlen = (len(encoded_pubkey) - 1) // 2
			self._x = _bytes2int(encoded_pubkey[1 : 1 + coordlen])
			self._y = _bytes2int(encoded_pubkey[1 + coordlen : ])
		else:
			raise Exception(NotImplemented)

	@property
	def curveid(self):
		return self._curveid

	@property
	def x(self):
		return self._x

	@property
	def y(self):
		return self._y

	@property
	def keytype(self):
		return "ecc"

	def __str__(self):
		return "ECCPublicKey<%s, (0x%x, 0x%x)>" % (self.curveid, self.x, self.y)

class _RSAPublicKey(_BasePublicKey):
	def __init__(self, n, e):
		_BasePublicKey.__init__(self)
		self._n = n
		self._e = e

	@property
	def n(self):
		return self._n

	@property
	def e(self):
		return self._e

	@property
	def keytype(self):
		return "rsa"

	def verify_md5sha1(self, data, signature, explain = None):
		assert(isinstance(data, bytes))
		assert(isinstance(signature, bytes))

		sig_int = bytes2int(signature)
		dec_int = pow(sig_int, self.e, self.n)
		dec_data = int2bytes(dec_int)
		dec = unpad_pkcs1(dec_data)

		if explain is not None:
			sv_explanation = ExplainedSteps("RSA signature verification MD5+SHA1")
			sv_explanation.append(ExplainedValueStep("RSA public key modulus (n)", self.n))
			sv_explanation.append(ExplainedValueStep("RSA public key public exponent (e)", self.e))
			sv_explanation.append(ExplainedValueStep("Signed data", data))
			sv_explanation.append(ExplainedValueStep("Signature", signature))
			sv_explanation.append(ExplainedValueStep("Signature integer representation", sig_int))
			sv_explanation.append(ExplainedModularExponentiationStep(sig_int, self.e, self.n))
			sv_explanation.append(ExplainedValueStep("Unpadded PKCS#1", dec))
			sv_explanation.append(ExplainedValueStep("Signed data MD5", hashlib.md5(data).digest()))
			sv_explanation.append(ExplainedValueStep("Signed data SHA1", hashlib.sha1(data).digest()))
			explain.append(sv_explanation)

		assert(len(dec) == 16 + 20)

		expect_hash = hashlib.md5(data).digest() + hashlib.sha1(data).digest()
		return expect_hash == dec


	def __str__(self):
		return "RSAPublicKey<0x%x, 0x%x>" % (self.n, self.e)

class PublicKey(object):
	def from_asn1(asn1):
		main_oid = asn1[0][0]
		sub_oid = asn1[0][1]

		main_type = type(main_oid.subtype()).__name__
		sub_type = type(sub_oid.subtype()).__name__

		if (main_type == "ObjectIdentifier") and (sub_type == "Null") and (str(main_oid) == "1.2.840.113549.1.1.1"):
			rsaparams = der_decode(asn1_bitstring_to_bytes(asn1[1]))
			return _RSAPublicKey(int(rsaparams[0]), int(rsaparams[1]))
		elif (main_type == "ObjectIdentifier") and (sub_type == "ObjectIdentifier") and (str(main_oid) == "1.2.840.10045.2.1"):
			curve_id = {
				"1.3.132.0.34":			"secp384r1",
				"1.2.840.10045.3.1.7":	"prime256v1",
			}.get(str(sub_oid))
			if curve_id is None:
				print(sub_oid)
				raise Exception(NotImplemented)

			return _ECCPublicKey(curve_id, asn1_bitstring_to_bytes(asn1[1]))
		else:
			print("MainOID, SubOID:", main_oid, sub_oid)
			raise Exception(NotImplemented)

