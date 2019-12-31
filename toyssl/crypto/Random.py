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

def secure_rand(length):
	f = open("/dev/urandom", "rb")
	data = f.read(length)
	assert(len(data) == length)
	f.close()
	return data


def secure_rand_int(max_value):
	"""Yields a value 0 <= return < maxvalue."""
	assert(max_value >= 2)
	bytecnt = ((max_value - 1).bit_length() + 7) // 8
	max_bin_value = 256 ** bytecnt
	wholecnt = max_bin_value // max_value
	cutoff = wholecnt * max_value
	while True:
		rnd = sum((value << (8 * bytepos)) for (bytepos, value) in enumerate(secure_rand(bytecnt)))
		if rnd < cutoff:
			break
	return rnd % max_value

if __name__ == "__main__":
	i = secure_rand_int(129)
	print(i)
