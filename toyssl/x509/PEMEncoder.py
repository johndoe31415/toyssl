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

import base64

def pem_encode(derdata, name):
	assert(isinstance(derdata, bytes))
	assert(isinstance(name, str))
	lines = [ ]
	lines.append("-----BEGIN %s-----" % (name))
	pemdata = base64.b64encode(derdata).decode("utf-8")
	for i in range(0, len(pemdata), 64):
		lines.append(pemdata[i : i + 64])
	lines.append("-----END %s-----" % (name))
	return lines

def pem_decode(pemdata, name):
	assert(isinstance(pemdata, list))
	assert(isinstance(name, str))
	data = None
	for line in pemdata:
		if line == ("-----BEGIN %s-----" % (name)):
			data = [ ]
		elif line == ("-----END %s-----" % (name)):
			return base64.b64decode("".join(data).encode("utf-8"))
		elif data is not None:
			data.append(line)
	raise Exception(NotImplemented)

def pem_readfile(filename, name):
	assert(isinstance(filename, str))
	assert(isinstance(name, str))
	lines = open(filename, "r").read().split("\n")
	return pem_decode(lines, name)

if __name__ == "__main__":
	pem = pem_readfile("../../server.crt", "CERTIFICATE")
	print(pem)
