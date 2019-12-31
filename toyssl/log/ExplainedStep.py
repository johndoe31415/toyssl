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

class _BaseStep(object):
	def dump(self, indent = 0):
		spc = "   " * indent
		print("%s%s" % (spc, str(self)))
		if self.childcnt > 0:
			for step in self._steps:
				step.dump(indent + 1)
	
	def flatten(self, indent = 0):
		yield (self, indent)
		if self.childcnt > 0:
			for step in self._steps:
				yield from step.flatten(indent + 1)

	@property
	def childcnt(self):
		return 0

class ExplainedValueStep(_BaseStep):
	def __init__(self, name, value):
		_BaseStep.__init__(self)
		self._name = name
		self._value = value

	def __str__(self):
		if isinstance(self._value, int):
			if self._value < 10:
				return "%s = %d" % (self._name, self._value)
			else:
				return "%s = 0x%x" % (self._name, self._value)
		elif isinstance(self._value, bytes):
			return "%s = %s" % (self._name, "".join("%02x" % (c) for c in self._value))
		else:
			return "%s = %s" % (self._name, str(self._value))

class ExplainedFunctionValueStep(ExplainedValueStep):
	def __init__(self, extype, name, value):
		ExplainedValueStep.__init__(self, name, value)
		assert(extype in [ "input", "output" ])
		self._extype = extype

	def __str__(self):
		super_str = super().__str__()
		return "[%s] %s" % (self._extype, super_str)
	

class ExplainedModularExponentiationStep(_BaseStep):
	"""Performs (a ^ b) % n"""
	def __init__(self, a, b, n):
		_BaseStep.__init__(self)
		assert(isinstance(a, int))
		assert(isinstance(b, int))
		assert(isinstance(n, int))
		self._a = a
		self._b = b
		self._n = n
		self._result = pow(self._a, self._b, self._n)
			
	def __str__(self):
		return "(0x%x ^ 0x%x) %% 0x%x = 0x%x" % (self._a, self._b, self._n, self._result)

class ExplainedSteps(_BaseStep):
	def __init__(self, stepname):
		_BaseStep.__init__(self)
		self._stepname = stepname
		self._steps = [ ]

	def append(self, step):
		self._steps.append(step)
		return self

	def __iter__(self):
		return iter(self._steps)

	@property
	def childcnt(self):
		return len(self._steps)

	def __str__(self):
		return "Explained: %s (%d steps)" % (self._stepname, len(self._steps))

