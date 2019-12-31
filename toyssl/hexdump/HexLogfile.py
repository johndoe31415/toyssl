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

from .HTMLHexDump import HTMLHexDump, htmlify
from .Intervals import Intervals, Interval

class HexLogfile(object):
	def __init__(self, outfilename):
		self._filename = outfilename
		self._f = open(outfilename, "w")
		self._append_file("hexdump_header.html")
		self._idcnt = 0
		self._namecnt = 0

	def _append_file(self, filename):
		for line in open(filename, "r"):
			line = line.rstrip("\r\n")
			self.print(line)

	def print(self, line):
		print(line, file = self._f, end = "")
		return self

	def _getuid(self):
		idvalue = "i%d" % (self._idcnt)
		self._idcnt += 1
		return idvalue

	def _msgbuf_to_intervals(self, msgbuffer):
		intervals = Intervals()
		markers = [ ]
		for marker in msgbuffer.markers:
			span_name = "n%d" % (self._namecnt)
			self._namecnt += 1
			markers.append((span_name, marker))
			if marker.endoffset > marker.startoffset:
				intervals.add(Interval(start = marker.startoffset, end = marker.endoffset, name = span_name))
		return (intervals, markers)

	def append(self, msgbuffer, heading = None):
		if heading is not None:
			self.print("<div class=\"pkt_heading\">%s</div>\n" % (heading))
			
		self.print("Packet length is %d bytes<br />\n" % (len(msgbuffer)))

		# Convert message buffer markers to intervals first
		(intervals, markers) = self._msgbuf_to_intervals(msgbuffer)

		# Output hex dump
		self.print("<pre class=\"hexdump\">")
		for line in HTMLHexDump(self._getuid).dump(msgbuffer.data, intervals):
			self.print(line + "\n")
		self.print("</pre>\n\n")

		# Then output the links
		current_depth = 1
		for (span_name, marker) in markers:
			if marker.depth < 1:
				continue
			if marker.depth > current_depth:
				self.print("<ul>" * (marker.depth - current_depth))
				current_depth = marker.depth
			elif marker.depth < current_depth:
				self.print("</ul>\n" * (current_depth - marker.depth))
				current_depth = marker.depth
			self.print("<li dep=\"%d\"><span name=\"%s\" id=\"%s\" onMouseOver='highlight(\"%s\")' onMouseOut='defaultHighlight()'>%s</span>" % (marker.depth, span_name, self._getuid(), span_name, htmlify(marker.text)))
			if len(marker.comments) == 1:
				self.print(": <span class=\"comment\">%s</span>" % (marker.comments[0]))
			else:
				for comment in marker.comments:
					self.print("<br /><span class=\"comment\">%s</span>" % (htmlify(comment)))
			self.print("</li>\n")
				
		self.print("</ul>\n" * (current_depth))
		self.print("<hr />\n")

		return self
	
	def append_explanation(self, explanation):
		current_depth = 0
		self.print("<div class=\"pkt_explanation\">%s</div>\n" % (str(explanation)))
		for (explstep, depth) in explanation.flatten():
			if depth > current_depth:
				self.print("<ul>" * (depth - current_depth))
				current_depth = depth
			elif depth < current_depth:
				self.print("</ul>\n" * (current_depth - depth))
				current_depth = depth
			self.print("<li>%s</li>" % (str(explstep)))
		self.print("</ul>\n" * (current_depth))
		self.print("<hr />\n")

	def close(self):
		self._append_file("hexdump_footer.html")
		self._f.close()
		self._f = None

	def __str__(self):
		return "HexLogfile<%s>" % (self._filename)

