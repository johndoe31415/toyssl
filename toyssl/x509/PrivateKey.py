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
import pyasn1.codec.der.decoder
from toyssl.x509.X509ASN1Model import PrivateKeyInfo, PrivateKeyInfoRSA
from toyssl.crypto.BinInt import bytes2int, int2bytes, pad_pkcs1

class _BasePrivateKey(object):
	def __init__(self):
		pass
	
	@property
	def pubkey(self):
		raise Exception(NotImplemented)

	@property
	def keytype(self):
		raise Exception(NotImplemented)

class _RSAPrivateKey(_BasePrivateKey):
	def __init__(self, n, d, e):
		assert(isinstance(n, int))
		assert(isinstance(d, int))
		assert(isinstance(e, int))
		_BasePrivateKey.__init__(self)
		self._n = n
		self._d = d
		self._e = e

	@property
	def n(self):
		return self._n
	
	@property
	def d(self):
		return self._d

	@property
	def e(self):
		return self._e

	@property
	def keytype(self):
		return "rsa"

	def sign_md5sha1(self, data):
		assert(isinstance(data, bytes))
		signature_length = (self._n.bit_length() + 7) // 8
		signature = hashlib.md5(data).digest() + hashlib.sha1(data).digest()
		padded_signature = pad_pkcs1(signature, signature_length)
		sig_int = bytes2int(padded_signature)

		enc_int = pow(sig_int, self.d, self.n)
		enc_data = int2bytes(enc_int)
		return enc_data

	@staticmethod
	def from_der(derdata):
		assert(isinstance(derdata, bytes))
		(decoded, tail) = pyasn1.codec.der.decoder.decode(derdata, asn1Spec = PrivateKeyInfoRSA())
		assert(len(tail) == 0)
		return _RSAPrivateKey(int(decoded["modulus"]), int(decoded["privateExponent"]), int(decoded["publicExponent"]))

	def __str__(self):
		return "RSAPrivateKey<0x%x, 0x%x, d = 0x%x>" % (self.n, self.e, self.d)

class PrivateKey(object):
	@staticmethod
	def from_asn1(asn1):
		if str(asn1["privateKeyAlgorithm"]["algorithm"]) == "1.2.840.113549.1.1.1":
			# RSA private key
			return _RSAPrivateKey.from_der(bytes(asn1["privateKey"]))
		else:
			raise Exception(NotImplemented)

	@staticmethod
	def from_der(derdata):
		assert(isinstance(derdata, bytes))
		(decoded, tail) = pyasn1.codec.der.decoder.decode(derdata, asn1Spec = PrivateKeyInfo())
		assert(len(tail) == 0)
		return PrivateKey.from_asn1(decoded)
