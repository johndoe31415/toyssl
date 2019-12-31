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

#!/usr/bin/python3
from pyasn1.type import tag, namedtype, namedval, univ, constraint, char, useful

class DirectoryString(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("teletexString", char.TeletexString()),
		namedtype.NamedType("printableString", char.PrintableString()),
		namedtype.NamedType("universalString", char.UniversalString()),
		namedtype.NamedType("utf8String", char.UTF8String()),
		namedtype.NamedType("bmpString", char.BMPString())
#		namedtype.NamedType("ia5String", char.IA5String())
	)

class AttributeValue(DirectoryString): pass

class AttributeType(univ.ObjectIdentifier): pass

class AttributeTypeAndValue(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("type", AttributeType()),
		namedtype.NamedType("value", AttributeValue())
		)

class RelativeDistinguishedName(univ.SetOf):
	componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
	componentType = RelativeDistinguishedName()

class Name(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("", RDNSequence())
		)

class AlgorithmIdentifier(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
		namedtype.OptionalNamedType("parameters", univ.Null())
		# XXX syntax screwed?
#		namedtype.OptionalNamedType('parameters', univ.ObjectIdentifier())
		)

class Extension(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("extnID", univ.ObjectIdentifier()),
		namedtype.DefaultedNamedType("critical", univ.Boolean("False")),
		namedtype.NamedType("extnValue", univ.OctetString())
		)

class Extensions(univ.SequenceOf):
	componentType = Extension()
	sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, 99)

class SubjectPublicKeyInfo(univ.Sequence):
	 componentType = namedtype.NamedTypes(
		 namedtype.NamedType("algorithm", AlgorithmIdentifier()),
		 namedtype.NamedType("subjectPublicKey", univ.BitString())
		 )

class UniqueIdentifier(univ.BitString): pass

class Time(univ.Choice):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("utcTime", useful.UTCTime()),
		namedtype.NamedType("generalTime", useful.GeneralizedTime())
		)

class Validity(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("notBefore", Time()),
		namedtype.NamedType("notAfter", Time())
		)

class CertificateSerialNumber(univ.Integer): pass

class Version(univ.Integer):
	namedValues = namedval.NamedValues(
		("v1", 0), ("v2", 1), ("v3", 2)
		)

class TBSCertificate(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.DefaultedNamedType("version", Version("v1", tagSet = Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))),
		namedtype.NamedType("serialNumber", CertificateSerialNumber()),
		namedtype.NamedType("signature", AlgorithmIdentifier()),
		namedtype.NamedType("issuer", Name()),
		namedtype.NamedType("validity", Validity()),
		namedtype.NamedType("subject", Name()),
		namedtype.NamedType("subjectPublicKeyInfo", SubjectPublicKeyInfo()),
		namedtype.OptionalNamedType("issuerUniqueID", UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
		namedtype.OptionalNamedType("subjectUniqueID", UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
		namedtype.OptionalNamedType("extensions", Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
		)

class ASN1Certificate(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("tbsCertificate", TBSCertificate()),
		namedtype.NamedType("signatureAlgorithm", AlgorithmIdentifier()),
		namedtype.NamedType("signatureValue", univ.BitString())
		)

class AuthorityKeyIdentifier(univ.Sequence):
	"""OID 2.5.29.35"""
	componentType = namedtype.NamedTypes(
		namedtype.OptionalNamedType("keyIdentifier", univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
		namedtype.OptionalNamedType("authorityCertIssuer", univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
#		namedtype.OptionalNamedType("authorityCertSerialNumber", univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
	)

class PrivateKeyInfo(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", univ.Integer()),
		namedtype.NamedType("privateKeyAlgorithm", AlgorithmIdentifier()),
		namedtype.NamedType("privateKey", univ.OctetString()),
	)

class PrivateKeyInfoRSA(univ.Sequence):
	componentType = namedtype.NamedTypes(
		namedtype.NamedType("version", univ.Integer()),
		namedtype.NamedType("modulus", univ.Integer()),
		namedtype.NamedType("publicExponent", univ.Integer()),
		namedtype.NamedType("privateExponent", univ.Integer()),
		namedtype.NamedType("prime1", univ.Integer()),
		namedtype.NamedType("prime2", univ.Integer()),
		namedtype.NamedType("exponent1", univ.Integer()),
		namedtype.NamedType("exponent2", univ.Integer()),
		namedtype.NamedType("coefficient", univ.Integer()),
	)

#der = open("x", "rb").read()
#
#(crt, tail) = decoder.decode(der, asn1Spec = Certificate())
#print(crt["tbsCertificate"]["extensions"][1])
#subdata = bytes(crt["tbsCertificate"]["extensions"][1][2])
#
#(indata, tail) = decoder.decode(subdata, asn1Spec = AuthorityKeyIdentifier())
#print(indata["authorityCertIssuer"])
#print(indata)
