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

class Comparable(object):
	@property
	def cmpkey(self):
		raise Exception(NotImplemented)

	@staticmethod
	def cmpadapt(other):
		"""Adapt any given type to this object in case comparison is
		necessary."""
		return other

	def __eq__(self, other):
		return self.cmpkey == self.cmpadapt(other).cmpkey

	def __ne__(self, other):
		return self.cmpkey != self.cmpadapt(other).cmpkey

	def __lt__(self, other):
		return self.cmpkey < self.cmpadapt(other).cmpkey

	def __le__(self, other):
		return self.cmpkey <= self.cmpadapt(other).cmpkey

	def __gt__(self, other):
		return self.cmpkey > self.cmpadapt(other).cmpkey

	def __ge__(self, other):
		return self.cmpkey >= self.cmpadapt(other).cmpkey

	def __hash__(self):
		return hash(self.cmpkey)
