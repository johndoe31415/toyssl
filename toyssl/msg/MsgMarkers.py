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

class MarkerSetterContext(object):
	def __init__(self, markernode, tellfunction):
		self._markernode = markernode
		self._tellfunction = tellfunction

	def enter(self):
		self._markernode._parent.ctx_enter()
		self._markernode.set_startoffset(self._tellfunction())
		return self._markernode

	def exit(self):
		self._markernode.set_endoffset(self._tellfunction())
		self._markernode._parent.ctx_leave()

	def __enter__(self):
		return self.enter()

	def __exit__(self, *args):
		return self.exit()

_AbsoluteMarker = collections.namedtuple("AbsoluteMarker", [ "order", "depth", "startoffset", "endoffset", "text", "comments" ])

class MarkerNode(object):
	def __init__(self, startoffset, endoffset, text = None, parent = None):
		self._startoffset = startoffset
		self._endoffset = endoffset
		self._text = text
		self._parent = parent
		self._children = [ ]
		self._comments = [ ]
		self._active_context = [ ]

	def clear(self):
		self._children = [ ]
		self._comments = [ ]
		self._active_context = [ ]

	def set_startoffset(self, startoffset):
		assert(self._startoffset is None)
		self._startoffset = startoffset
	
	def set_endoffset(self, endoffset):
		assert(self._endoffset is None)
		self._endoffset = endoffset
	
	def add_comment(self, comment):
		self._comments.append(comment)
		return self

	def relocate(self, offset, new_parent = None):		
		parent = MarkerNode(self.startoffset + offset, self.endoffset + offset, self.text, new_parent)
		parent._comments = list(self._comments)
		for child in self._children:
			parent._children.append(child.relocate(offset, parent))
		return parent
	
	@property
	def comments(self):
		return tuple(self._comments)

	def new_marker(self, startoffset, endoffset, text):
		parent = self.activenode
		child_node = MarkerNode(startoffset, endoffset, text, parent = parent)
		parent._children.append(child_node)
		return child_node

	@property
	def text(self):
		return self._text

	@property
	def startoffset(self):
		return self._startoffset

	@property
	def endoffset(self):
		return self._endoffset
	
	def rawdump(self):
		for marker in self.flatten():
			print(marker)

	def dump(self, depth = 0):
		spc = "   " * depth
		#print("%s%s [0x%x - 0x%x]" % (spc, self.text, self.startoffset, self.endoffset))
		print("%s%s [%d - %d]" % (spc, self.text, self.startoffset, self.endoffset))
		for comment in self._comments:
			print("%s{%s}" % (spc, comment))
		for child in self._children:
			child.dump(depth + 1)

	def flatten(self, flat_list = None, depth = 0):
		if flat_list is None:
			flat_list = [ ]
		flat_list.append(_AbsoluteMarker(order = depth, depth = depth, startoffset = self.startoffset, endoffset = self.endoffset, text = self.text, comments = self.comments))
		for child in self._children:
			child.flatten(flat_list, depth + 1)
		return flat_list

	@property
	def activenode(self):
		if len(self._active_context) == 0:
			return self
		else:
			return self._active_context[-1]

	def ctx_enter(self):
		self._active_context.append(self._children[-1])
	
	def ctx_leave(self):
		self._active_context.pop()

	def new_context(self, text, tellfunction):
		child = self.activenode.new_marker(None, None, text)
		return MarkerSetterContext(child, tellfunction)

	def join(self, other, offset):
		"""Join other markers to current markers."""
		for childmarker in other._children:
			self.activenode._children.append(childmarker.relocate(offset))

	def __iter__(self):
		yield from self.flatten()

	def __str__(self):
		return "MsgMarkers<%d [%s]>" % (len(self._children), self._text)
