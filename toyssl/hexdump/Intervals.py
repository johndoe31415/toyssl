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

import collections

# Interval start is inclusive, end is exclusive
Interval = collections.namedtuple("Interval", [ "start", "end", "name" ])

class Intervals(object):
	def __init__(self):
		self._intervals = [ ]

	@staticmethod
	def _interval_a_contained_in_b(a, b):
		return (b.start <= a.start < b.end) and (b.start < a.end <= b.end)

	@staticmethod
	def _interval_a_before_b(a, b):
		return a.end == b.start

	@staticmethod
	def _interval_a_overlaps_b(a, b):
		return (a.start <= b.start < a.end) or (a.start <= b.end < a.end)

	@staticmethod
	def _interval_intersection(a, b, name):
		return Interval(start = max(a.start, b.start), end = min(a.end, b.end), name = name)

	def intersect(self, intersection_interval):
		intvls = Intervals()
		for interval in self._intervals:
			isect = self._interval_intersection(interval, intersection_interval, interval.name)
			if isect.end > isect.start:
				intvls.add(isect)
		return intvls

	def add(self, interval):
		assert(interval.end > interval.start)
		self._intervals.append(interval)

	def dump(self):
		for interval in self._intervals:
			print(interval)

	def walk(self, value):
		special = [ ]
		for interval in self._intervals:
			if interval.start == value:
				special.append((interval.name, "start"))
			if interval.end == value + 1:
				special.append((interval.name, "end"))
			if interval.start < value < interval.end:
				special.append((interval.name, "in"))
		return special

	def __len__(self):
		return len(self._intervals)

	def __str__(self):
		return "Intervals(%d)" % (len(self))

if __name__ == "__main__":
	maxlen = 7
	contained_value = 0
	before_value = 0
	overlap_value = 0
	for a in range(maxlen):
		for b in range(a + 1, maxlen):
			for c in range(maxlen):
				for d in range(c + 1, maxlen):
					ia = Interval(start = a, end = b, name = "ia")
					ib = Interval(start = c, end = d, name = "ib")
					flag_contained = Intervals._interval_a_contained_in_b(ia, ib)
					flag_before = Intervals._interval_a_before_b(ia, ib)
					flag_overlap = Intervals._interval_a_overlaps_b(ia, ib)

					contained_value = (contained_value << 1) | [0, 1][flag_contained]
					before_value = (before_value << 1) | [0, 1][flag_before]
					overlap_value = (overlap_value << 1) | [0, 1][flag_overlap]
#					print(ia, ib, flag_overlap)

#	print(hex(overlap_value))
	assert((maxlen == 7) and (contained_value == 0x1f80007c0001e00007000018000040003ff000f780039c000c600021000f7f8039dc00c66002110073bf018cd804224063378108940844b))
	assert((maxlen == 7) and (before_value == 0x7c00001e00000e00000c0000100000000f000007000006000008000000007000006000008000000000c00001000000000040000000000))
	assert((maxlen == 7) and (overlap_value == 0x1f8000ffe007fff03ffff1ffffefffffc1f0030ff81c7ff8f3fff7dfffd08780c63f8739ff3deffc844706333e39ddf8844986336e10895))


	ivls = Intervals()
	ivls.add(Interval(start = 10, end = 20, name = "MooKoo1"))
	ivls.add(Interval(start = 12, end = 15, name = "MooKoo2"))
	ivls.add(Interval(start = 3, end = 18, name = "MooKoo3"))
	ivls.dump()

	print("-" * 60)
	ivls = ivls.intersect(Interval(start = 8, end = 15, name = None))
	ivls.dump()

	for i in range(20):
		print(i, ivls.walk(i))
