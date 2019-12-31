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

def bytes2int(data):
	assert(isinstance(data, bytes))
	int_value = sum((value << (8 * pos)) for (pos, value) in enumerate(reversed(data)))
	return int_value

def int2bytes(value):
	result = [ ]
	while value > 0:
		result.insert(0, value & 0xff)
		value >>= 8
	return bytes(result)

def pad_pkcs1(data, length):
	"""Pad PKCS#1 data."""
	ff_count = length - len(data) - 3
	if ff_count <= 0:
		raise Exception("Cannot PKCS#1 pad data of length %d bytes to a total of %d bytes." % (len(data), length))
	padded = bytearray([ 0x00, 0x01 ])
	padded += ff_count * bytes([ 0xff ])
	padded += bytes([ 0x00 ])
	padded += data
	return bytes(padded)

def unpad_pkcs1(data):
	"""Unpad PKCS#1 data. Does raise an exception, so it is susceptible to
	padding oracle attacks. Do not use except for testing purposes."""
	if data[0] != 0x01:
		raise Exception("Padding does not start with 0x01.")
	for i in range(1, len(data)):
		if data[i] == 0xff:
			continue
		else:
			break
	if data[i] != 0x00:
		raise Exception("Padding does not end with 0x00.")
	unpadded = data[i + 1:]
	return unpadded
