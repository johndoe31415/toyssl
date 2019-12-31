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

from .Intervals import Interval

def htmlify(value):
	if value is None:
		value = ""
	value = value.replace("&", "&amp;")
	value = value.replace("<", "&lt;")
	value = value.replace(">", "&gt;")
	return value

class HTMLHexDump(object):
	def __init__(self, idfnc = None):
		self._width = 16
		self._spacers = [ 1, 8 ]
		self._idfnc = idfnc

	def _get_prefix(self, offset):
		return "%6x  " % (offset)

	def _get_hexpart(self, offset, data, intervals):
		asciipart = ""
		openspans = 0
		for charindex in range(self._width):
			special = [ value for value in intervals.walk(offset + charindex) if (value[1] in [ "start", "end" ]) ]
			for (iname, iaction) in special:
				if iaction == "start":
					asciipart += "<span name=\"%s\" id=\"%s\">" % (iname, self._idfnc())
					openspans += 1

			if charindex >= len(data):
				asciipart += "  "
			else:
				asciipart += "%02x" % (data[charindex])

			for (iname, iaction) in special:
				if iaction == "end":
					asciipart += "</span>"
					openspans -= 1

			for spacer in self._spacers:
				if ((charindex + 1) % spacer) == 0:
					asciipart += " "
		asciipart += "</span>" * openspans
		return asciipart

	def _get_asciipart(self, offset, data, intervals):
		hexpart = ""
		openspans = 0
		for charindex in range(self._width):
			special = [ value for value in intervals.walk(offset + charindex) if (value[1] in [ "start", "end" ]) ]
			for (iname, iaction) in special:
				if iaction == "start":
					hexpart += "<span name=\"%s\" id=\"%s\">" % (iname, self._idfnc())
					openspans += 1

			if charindex >= len(data):
				hexpart += " "
			else:
				if 32 < data[charindex] < 127:
					hexpart += htmlify(chr(data[charindex]))
				else:
					hexpart += "."

			for (iname, iaction) in special:
				if iaction == "end":
					hexpart += "</span>"
					openspans -= 1
		hexpart += "</span>" * openspans
		return hexpart

	def _dumpline(self, offset, data, intervals):
		# Intersect intervals with the markers for current line
		line_interval = Interval(start = offset, end = offset + self._width, name = None)
		intervals = intervals.intersect(line_interval)

		line = [ ]
		line.append(self._get_prefix(offset))
		line.append(self._get_hexpart(offset, data, intervals))
		line.append("|")
		line.append(self._get_asciipart(offset, data, intervals))
		line.append("|")
		return "".join(line)

	def dump(self, data, intervals):
		return [ self._dumpline(i, data[i : i + self._width], intervals) for i in range(0, len(data), self._width) ]

if __name__ == "__main__":
	from .Intervals import Interval
	intervals = Intervals()
	intervals.add(Interval(start = 0, end = 1, name = "moo"))
#	intervals.add(Interval(start = 5, end = 7, name = "koo"))
	data = "Hallo das ist ein cooler Test und hier sehe ich den utf8 Ümläut!".encode("utf-8")
	dumper = HTMLHexDump()
	for line in dumper.dump(data, intervals):
		print(line)

