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

import datetime
import collections
from toyssl.hexdump import HexLogfile

_LogEntry = collections.namedtuple("LogEntry", [ "ts", "logtype", "data" ])

class ConnectionLogger(object):
	_RXTX_ARROWS = "←→"
#	_RXTX_ARROWS = "⇐⇒"

	def __init__(self):
		self._entries = [ ]

	def writelog(self, filename):
		outfile = HexLogfile(filename)
		for entry in self._entries:
			if entry.logtype in [ "rx_packet", "tx_packet" ]:
				layered_pkt = entry.data
				heading = {
					"rx_packet":		"<span class=\"arrow_rx\">%s</span> " % (self._RXTX_ARROWS[0]),
					"tx_packet":		"<span class=\"arrow_tx\">%s</span> " % (self._RXTX_ARROWS[1]),
				}[entry.logtype]
				heading += layered_pkt.application.packet_type().name
				outfile.append(layered_pkt.data, heading = heading)
			elif entry.logtype == "explanation":
				outfile.append_explanation(entry.data)

	def _add_entry(self, logtype, data):
		entry = _LogEntry(ts = datetime.datetime.now(), logtype = logtype, data = data)
		self._entries.append(entry)

	def rx_packet(self, pkt):
		self._add_entry("rx_packet", pkt)
	
	def rx_rawdata(self, data):
		self._add_entry("rx_rawdata", data)
	
	def tx_packet(self, pkt):
		self._add_entry("tx_packet", pkt)
	
	def tx_rawdata(self, data):
		self._add_entry("rx_rawdata", data)

	def explain(self, data):
		self._add_entry("explanation", data)
