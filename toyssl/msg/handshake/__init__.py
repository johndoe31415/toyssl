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

from .ClientHelloPkt import ClientHelloPkt
from .ServerHelloPkt import ServerHelloPkt
from .CertificatePkt import CertificatePkt
from .ServerKeyExchangePkt import ServerKeyExchangePkt
from .ClientKeyExchangePkt import ClientKeyExchangePkt
from .ServerHelloDonePkt import ServerHelloDonePkt
from ..Enums import HandshakeType

_KNOWN_HANDSHAKE_PACKETS = {
	HandshakeType.ClientHello: ClientHelloPkt,
	HandshakeType.ServerHello: ServerHelloPkt,
	HandshakeType.Certificate: CertificatePkt,
	HandshakeType.ServerKeyExchange: ServerKeyExchangePkt,
	HandshakeType.ServerHelloDone: ServerHelloDonePkt,
	HandshakeType.ClientKeyExchange: ClientKeyExchangePkt,
}

def parse_handshake_pkt(msgbuf):
	msgbuf.seek(0)
	packet_type = HandshakeType(msgbuf.get_uint8())
	handler = _KNOWN_HANDSHAKE_PACKETS[packet_type]
	return handler.parse(msgbuf)
