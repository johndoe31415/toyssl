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
from toyssl.msg.MsgBuffer import MsgBuffer
from toyssl.msg.handshake import ClientHelloPkt
from toyssl.msg.Enums import SSLVersion, CipherSuite, CompressionMethod

class PacketTest(unittest.TestCase):
	def test_chello_apppkt(self):
		app_pkt = ClientHelloPkt(SSLVersion.ProtocolTLSv1_2)
		app_pkt.add_cipher_suite(CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA)
		app_pkt.add_compression_method(CompressionMethod.null)

		msgbuf = app_pkt.serialize()
		self.assertTrue(isinstance(msgbuf, MsgBuffer))

		data = msgbuf.data
		self.assertTrue(isinstance(data, bytes))

		msgbuf.hexdump()
		self.assertEqual(data[0 : 2], b"\x03\x03")
