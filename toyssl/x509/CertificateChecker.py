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

import math
import collections

CheckResult = collections.namedtuple("CheckResult", [ "code", "text", "level" ])

class CertificateChecker(object):
	def __init__(self, x509):
		self._x509 = x509

	@staticmethod
	def _rsa_securitybits_to_keybits(secbits):
		coeffs = [ 844.7816, -19.05282, 0.29686 ]
		x = secbits
		y = sum(value * (x ** exponent) for (exponent, value) in enumerate(coeffs))
		return round(y)

	@staticmethod
	def _rsa_keybits_to_securitybits(keybits):
		(a, b, c) = [ 844.7816, -19.05282, 0.29686 ]
		y = keybits
		x = (-b + math.sqrt((b ** 2) + (4 * c * y) - (4 * a * c))) / (2 * c)
		return round(x)

	@staticmethod
	def _rsa_suggested_keylength_for_securitybits(secbits):
		multiple = 1024
		keybits = CertificateChecker._rsa_keybits_to_securitybits(secbits)
		keybits = (keybits + multiple - 1) // multiple * multiple
		return keybits

	def _get_cryptosystem_security_level_bits(self):
		pubkey = self._x509.publickey
		if pubkey.keytype == "rsa":
			return self._rsa_keybits_to_securitybits(pubkey.n.bit_length())
		elif pubkey.keytype == "ecc":
			curve_security = {
				"secp384r1":	192,
				"prime256v1":	128,
			}
			secbits = curve_security.get(pubkey.curveid)
			if secbits is None:
				raise Exception(NotImplemented)
			return secbits
		else:
			raise Exception(NotImplemented)

	@staticmethod
	def _get_hashalg_security_level_bits(sigalg):
		alg = str(sigalg[0])
		if alg == "1.2.840.113549.1.1.10":			# rsassa-pss
			alg = str(sigalg[1][0][0])

		algorithm_strenghts = {
			"1.2.840.113549.1.1.2":			64,		# md2WithRSAEncryption
			"1.2.840.113549.1.1.4":			64,		# md5WithRSAEncryption
			"1.2.840.113549.1.1.5":			80,		# sha1-with-rsa-signature
			"1.2.840.113549.1.1.11":		128,	# sha256WithRSAEncryption
			"1.2.840.113549.1.1.12":		192,	# sha384WithRSAEncryption
			"1.2.840.113549.1.1.13":		256,	# sha512WithRSAEncryption
			"1.2.840.10045.4.3.3":			192,	# ecdsa-with-SHA384
			"2.16.840.1.101.3.4.2.1":		128,	# sha256
		}
		if alg not in algorithm_strenghts:
			raise Exception(NotImplemented)

		return algorithm_strenghts[alg]

	def _check_validity_time(self):
		validity_secs = (self._x509.valid_to - self._x509.valid_from).total_seconds()
		validity_years = validity_secs / 86400 / 365.25
		if validity_secs <= 0:
			yield ("Certificate can never be valid, 'valid from' is later than 'valid to'.", "error")
		elif validity_secs < (7 * 86400):
			yield ("Certificate validity is very short (shorter than one week).", "odd")
		elif validity_years > 10:
			yield ("Certificate validity is extremely long (%.1f years)." % (validity_years), "warn")
		elif validity_years > 4:
			yield ("Certificate validity is very long (%.1f years)." % (validity_years), "odd")

	def _check_rsa_publickey(self):
		pubkey = self._x509.publickey
		if pubkey.keytype == "rsa":
			if pubkey.e < 3:
				yield ("Broken exponent e used (0x%x)." % (pubkey.e), "error")
			elif pubkey.e == 3:
				yield ("Very small exponent e used (0x%x)." % (pubkey.e), "warn")
			elif pubkey.e <= 257:
				yield ("Small exponent e used (0x%x)." % (pubkey.e), "warn")
			elif pubkey.e not in [ 0x10001 ]:
				yield ("Unusual exponent e used (0x%x)." % (pubkey.e), "odd")

			if (pubkey.e % 2) == 0:
				yield ("Broken exponent e used (even number used, e = 0x%x)." % (pubkey.e), "error")

			bitlen = pubkey.n.bit_length()
			if bitlen < 1024:
				yield ("Broken short modulus n used (%d bit)." % (bitlen), "error")
			elif bitlen < 2048:
				yield ("Short modulus n used (%d bit)." % (bitlen), "warn")
			elif bitlen > 4096:
				yield ("Long modulus n used (%d bit)." % (bitlen), "odd")

			if (bitlen % 1024) != 0:
				yield ("Unusual modulus n used (%d bit not a multiple of 1024)." % (bitlen), "odd")

	def _check_subjissuer(self):
		for (name, value) in [ ("subject", self._x509.subject), ("issuer", self._x509.issuer) ]:
			if value.getfieldcnt("CN") == 0:
				yield ("Certificate has no common name in its %s." % (name), "odd")

			dupl = value.duplicate_list()
			if len(dupl) > 0:
				yield ("Certificate has multiple uses of the field(s) %s in its %s." % (", ".join(dupl), name), "warn")

			unknown = value.getunknownfields()
			if len(unknown) > 0:
				yield ("Certificate has unknown OIDs for field(s) %s in its %s." % (", ".join(unknown), name), "warn")

	def _check_version(self):
		if self._x509.version < 3:
			yield ("Old certificate Format used (X.509 v%d)." % (self._x509.version), "warn")

	def _check_sigalg_consistency(self):
		(alg1, alg2) = self._x509.signature_algs
		if (alg1 != alg2):
			yield ("Used signature algorithms different in header in footer (%s and %s), violation of RFC3280 5.1.2.2." % (alg1, alg2), "error")

	def _check_sigalg(self):
		alg = self._x509.signature_alg
		alg_strength = self._get_hashalg_security_level_bits(alg)
		key_strength = self._get_cryptosystem_security_level_bits()

		diff_percent = ((key_strength - alg_strength) / alg_strength) * 100
		absdiff = abs(diff_percent)
		if absdiff > 100:
			yield ("Gross mismatch of security (%+.1f%%) provided by signature algorithm (%d bits) and security provided by key (%d bits)." % (diff_percent, alg_strength, key_strength), "warn")
		elif absdiff > 30:
			yield ("Mismatch of security (%+.1f%%) provided by signature algorithm (%d bits) and security provided by key (%d bits)." % (diff_percent, alg_strength, key_strength), "odd")

		for (name, value) in [ ("algorithmic strength of signature algorithm", alg_strength), ("key strength of used public key", key_strength) ]:
			if value <= 64:
				yield ("Broken %s in certificate (%d bits)." % (name, value), "error")
			elif value <= 80:
				yield ("Weak %s in certificate (%d bits)." % (name, value), "warn")
			elif value <= 100:
				yield ("Moderate %s in certificate (%d bits)." % (name, value), "odd")

	def _check_x509_extensions(self):
		if (self._x509.version > 1) and (self._x509.extensions is None):
			yield ("Certificate is missing X.509 extension field.", "odd")

	def check(self):
		results = [ ]
		for methodname in dir(self):
			if methodname.startswith("_check_"):
				checkname = methodname[7:]
				method = getattr(self, methodname)
				for result in method():
					(text, level) = result
					results.append(CheckResult(code = checkname, text = text, level = level))

		return results
