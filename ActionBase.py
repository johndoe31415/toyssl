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
import logging

class _CustomLogFormatter(object):
	def format(self, record):
		created = datetime.datetime.fromtimestamp(record.created)
		msg = created.strftime("%Y-%m-%d %H:%M:%S")
		msg += ".%03d " % (created.microsecond // 1000)
		msg += "[%s] {%s:%d}: " % (record.levelname[0], record.module, record.lineno)
		msg += record.msg
		return msg

class ActionBase(object):
	def __init__(self, cmd, args):
		self._cmd = cmd
		self._args = args
		self._log = logging.getLogger("toyssl")
		self._setup_logging()
		self.run()

	def _setup_logging(self):
#		formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt = "%Y-%m-%d %H:%M:%S")
		formatter = _CustomLogFormatter()

		handler = logging.StreamHandler()
		handler.setLevel(logging.DEBUG)
		handler.setFormatter(formatter)

		self._log.addHandler(handler)
		self._log.setLevel(logging.DEBUG)

	def run(self):
		raise Exception(NotImplemented)
