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

import unittest
from toyssl.x509 import X509Certificate, ASN1PrettyPrinter

_CRTDATA = """
-----BEGIN CERTIFICATE-----
MIIC9TCCAd2gAwIBAgIJANQUkWQscoX7MA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
BAMMBkZvb2JhcjAeFw0xNTA2MjMwODQ5NTlaFw0xNTA3MjMwODQ5NTlaMBExDzAN
BgNVBAMMBkZvb2JhcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuD
PRTgUy+9vfcC3HjaeSsfCWFyd0DwIL5TdvgA/D/coW7+x9Q/wZfp1oWFXNN8Naeq
iGYp4GgZ/FUF4XRX0yuSB+yE9e2mQ5w0m72ug0uPTLVEKHOL0FMmxSu76tWnvq8+
O4NB/us9AQmC278TBcDdnQyXjRhMHBRRmRHo1H8Y1WGwS/r4qJhKLVPe3ALo/cUD
MF4CsycU9rqfqJk78wnVN+5AbbuHwplL2lTYLDjcQD7WknFJMa4DvlZRK41rk+FZ
Jb7+w0QiXFYqkucYUSQIMoeTjHbdY/PLJLqTfFghuQjcEQqauQhukALzA7pJa1oP
9rq4t6t8ZIh4hfneIkUCAwEAAaNQME4wHQYDVR0OBBYEFF3E66Z5dXIGVP/UWmXm
Ui8pXodoMB8GA1UdIwQYMBaAFF3E66Z5dXIGVP/UWmXmUi8pXodoMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAK5rOgPo1WcifG0kz/Mcklu/Es2+uss4
NUsVKVezQhMP+3rtMcgqFjQXS1YbrZG1RR1NU7X9uVcptjzDPR3b0tzwlD8OabHA
AU4/Z/I1QdQ2GJ0s6mRcdciNk/IevVPzGWr35ZerYTtsPdLlJrL0YRX5HDqAEgiu
Z5SfVmI7qhAUsG5p1a94ofI/OSt4PSGhqByqyu725qLl5WjO3KYbg3+WqamzMHnN
vpvgpyFv7gBaclsl2KgFHVmtleaqwe9YTfDL6wx5cVbme8n16HcWpOKzb9HxHb1Z
vta/GD8z0i9y9l4JIk5sZ7P2HGfqpWAgvgtI56xY6Ci8w5L8inhYeMk=
-----END CERTIFICATE-----
"""

class X509CrtParser(unittest.TestCase):
	def test_parse(self):
		crt = X509Certificate.frompemobj(_CRTDATA)


		#ASN1PrettyPrinter(crt.decoded).dump()

#		print(crt[0])
#		print(crt.decoded)
#		print(dir(crt.decoded))
#		print(crt.decoded.prettyPrint())

