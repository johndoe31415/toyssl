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

import threading
from .MsgBuffer import MsgBuffer

class BufferFifo(object):
	def __init__(self):
		self._lock = threading.Lock()
		self._data = MsgBuffer()

	def put(self, data):
		with self._lock:
			self._data += data

	def getrecordlayerpkt(self):
		with self._lock:
			if len(self._data) < 5:
				return
			self._data.seek(3)
			expect_length = self._data.get_uint16()

			if len(self._data) > expect_length:
				(head, self._data) = self._data.cut_head(expect_length + 5)
				return head



