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

import socket
import threading

from toyssl.msg.BufferFifo import BufferFifo
from toyssl.msg.MsgBuffer import MsgBuffer
from toyssl.log import ConnectionLogger

class _SocketRXThread(threading.Thread):
	def __init__(self, conn, callback):
		threading.Thread.__init__(self)
		self._quit = False
		self._conn = conn
		self._callback = callback

	def close(self):
		self._quit = True

	def run(self):
		while not self._quit:
			try:
				data = self._conn.recv(4096)
			except socket.timeout:
				continue
			if len(data) > 0:
				self._callback(data)

class SSLConnection(object):
	def __init__(self, protocol):
		self._conn = None
		self._rxthread = None
		self._rxbuffer = BufferFifo()
		self._protocol = protocol
		self._handler = None
		self._connlog = ConnectionLogger()

	@property
	def log(self):
		return self._connlog

	def set_handler(self, handler):
		self._handler = handler

	def rx_from_peer(self, data):
		self._connlog.rx_rawdata(data)
		self._rxbuffer.put(data)
		while True:
			next_pkt = self._rxbuffer.getrecordlayerpkt()
			if next_pkt is None:
				return
			next_pkt = MsgBuffer(next_pkt)
			layered_pkt = self._protocol.parse(next_pkt)
			self._connlog.rx_packet(layered_pkt)
			self._handler.rx_packet(layered_pkt)

	def tx_to_peer(self, data):
		self._conn.send(data)

	def set_peer_socket(self, conn):
		self._conn = conn
		self._rxthread = _SocketRXThread(self._conn, self.rx_from_peer)
		self._rxthread.start()

	def send_pkt(self, pkt):
		layered_pkt = self._protocol.serialize(pkt)
		self._handler.tx_packet(layered_pkt)
		self._connlog.tx_packet(layered_pkt)
		self.tx_to_peer(layered_pkt.data.data)

	def explain(self, explanation):
		self._connlog.explain(explanation)

