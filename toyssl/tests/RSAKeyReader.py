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
from toyssl.x509 import ASN1PrettyPrinter
from toyssl.x509.X509ASN1Model import PrivateKeyInfo
from toyssl.x509.PEMEncoder import pem_decode
from toyssl.x509.PrivateKey import PrivateKey

_KEYDATA = """
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCyBYbmpM66INfe
qJN+SOutpdPwl2PBko9zWjDChxFZsNeelfIFulMsmjfBfttiH3WhWEvTqIRNUdEJ
85nDVt2aV0pEMSTNFfMcBAEhSf+23i0J6ahhXsawZri/HU9aAQiPhU7w2evGqPbU
9iPhUfK5gSi9SAfXLf9k01FwyH5I0YMxtMkYBnkc7p5ZljM3GXzlg4zAr2FH0k+t
UXB6GJRh6oS23Ar7mNEqj7CEiVx6h+2yWtv/my2KZRv+pmXxGs+fLmKp6xILpy/g
gV3H7H7uiI64jeggL5/QwMrZmYHnEPc0BMdkY7237bSEeHFRiIYScbt0wCyYLPoA
vYM0drfjAgMBAAECggEBAI3oXfrpkWlJ2QrC8qAOXOCVefcllv2taPCZCplmtev7
TkY6XS03tCmv3ZY/G36CeXBeREO654wDFlGKgB341rm7r5XgXuelAaBpiMUSiecq
AFkQi4ri1Bu2JrsiECk8/af6qkzQSmSYN/rXIw7wFj7NuL3591YOcrHayebPy+sa
0qNV79xQSwTnzWilPVqtiyAjJ3pgJT7aRfZkudbPTo2aUfAbNOuRR2XTOfKTfRBp
EupsHWtiN4yEM5xfw7SQXzW0Rl+GQlKB6RYUQFEcQ2OnsE1MPZQS+MEd7tHidI7i
4pQLQbJwR6ullJtjg3VP+YmWmSialydYHWYn3IQIj9ECgYEA6Apx1TCLejFBWwdd
Hl8pDm/hi1/Iuy5II4hqaLjS0IpQ74XXb7hfiA5V5/QBmVYaQSy7IQFC711N2j3A
Z56HdHtI+DP6cZGIqpkefJ34gedmyGzbAC8g0COx9q3ztaAJpG03TndEnHcV+jjj
1DBYQoPgVNiscmrv1mdJ5OgdTu8CgYEAxGcwCqjsPoy3Hut2CnIO4frmNZGXh+jB
RuL2BiPhRfqpeMIM9hmcFIPfiomzvTQjVI4EmTGkfI2RkSeZ810rbB/K0RpPwvEY
wAX7DPcz+UPNQ8Ro1Ee7LdvaJrOnQY3SFuQE071VkkYFYx/cFcKvRlenpPby7Q+7
pA3HJST5pk0CgYANFgm1bDdxfLWi3JdzzwoRtl2R7qTzaXjICDl4DnRVLnfCClpM
Aqngkm5l1m0AqMpyQoOLKPcNaMWrOTBQp7Ab8Zf753KIVRzQAjKl9IK/UL2LMBhp
uj6vflPbBZRo+c2RaFdmJXPJHy4uHmc64D8aATX1kwKmsUE1Zj3UmwKMIQKBgQCw
6WXr5DdRLH1yu5QLWqwvQEqHbEq7YJxgluYXp9Ausdhf7yOvtmfSTutYJiuiPUmp
y3c26vGIRBkgUDSrc3w+m/CcJAA+z9+EcJ6wEihd2oYWCeCHfsmLSGMbw23gbbgV
aHU0qXJgHPSTUkpzy3cIfMKEpPEzOp3B66s7uS+rbQKBgQCb99LXdzomUsR51LnA
yX6cy1+RyaVIP+3BKq2O4/auiFPtzI23NpawL8vOHtMwcj0O6RSyJPq4nlqQZOhh
GAP7AsBgbaD7L7TpPy8xin2vnQ1soN7pZNy/z9BA4dy7zl5AxX4pQNuADN9KZjjf
8+dl/M8OvXmtiRMM4C0LOmUtAA==
-----END PRIVATE KEY-----
"""

class RSAKeyReaderTest(unittest.TestCase):
	def test_parse(self):
		derobj = pem_decode(_KEYDATA.split("\n"), "PRIVATE KEY")
		privkey = PrivateKey.from_der(derobj)
		
		m = 123456789
		c = pow(m, privkey.e, privkey.n)
		p = pow(c, privkey.d, privkey.n)
		self.assertEqual(m, p)

