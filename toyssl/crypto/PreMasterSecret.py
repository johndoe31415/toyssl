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

import hashlib
import Crypto.Hash.HMAC
import Crypto.Hash.MD5
import Crypto.Hash.SHA
import Crypto.Hash.SHA256
from toyssl.crypto.Enums import PMSCalcLabel, PMSPRF
from toyssl.log.ExplainedStep import ExplainedSteps, ExplainedFunctionValueStep, ExplainedValueStep

class PreMasterSecret(object):
	_CALCLABELS = {
		PMSCalcLabel.MasterSecret:		b"master secret",
		PMSCalcLabel.KeyExpansion:		b"key expansion",
		PMSCalcLabel.ServerFinished:	b"server finished",
		PMSCalcLabel.ClientFinished:	b"client finished",
	}

	_HASHFUNCTIONS = {
		PMSPRF.MD5: Crypto.Hash.MD5,
		PMSPRF.SHA1: Crypto.Hash.SHA,
		PMSPRF.SHA256: Crypto.Hash.SHA256,
	}

	@staticmethod
	def pms_to_ms(prf, prfcalclabel, premaster_secret, server_rnd, client_rnd, explain = None):
		assert(isinstance(prf, PMSPRF))
		assert(isinstance(prfcalclabel, PMSCalcLabel))
		assert(isinstance(premaster_secret, bytes))
		assert(isinstance(client_rnd, bytes))
		assert(isinstance(server_rnd, bytes))
		pms_to_ms_explanation = ExplainedSteps("Pre-master secret to master secret conversion")
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("input", "Pseudo random function (PRF)", str(prf)))
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("input", "Used calculation label", str(prfcalclabel)))
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("input", "Pre-master secret", premaster_secret))
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("input", "Server random nonce", server_rnd))
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("input", "Client random nonce", client_rnd))
		pms_to_ms_explanation.append(ExplainedValueStep("", ""))
	
		prf = PreMasterSecret._HASHFUNCTIONS[prf]
		label = PreMasterSecret._CALCLABELS[prfcalclabel]
		pms_to_ms_explanation.append(ExplainedValueStep("Binary label representation", label))

		hmac = Crypto.Hash.HMAC.new(digestmod = prf, key = premaster_secret)
		hmac.update(label)
		hmac.update(client_rnd)
		hmac.update(server_rnd)
		A = hmac.digest()
		pms_to_ms_explanation.append(ExplainedValueStep("HMAC input data for first round", label + client_rnd + server_rnd))
		pms_to_ms_explanation.append(ExplainedValueStep("HMAC result (A) of first round", A))
		pms_to_ms_explanation.append(ExplainedValueStep("", ""))

		expect_len = 48
		master = bytearray()
		round_no = 2
		while len(master) < expect_len:
			hmac = Crypto.Hash.HMAC.new(digestmod = prf, key = premaster_secret)
			hmac.update(A)
			hmac.update(label)
			hmac.update(client_rnd)
			hmac.update(server_rnd)
			nextblock = hmac.digest()
			master += nextblock
			pms_to_ms_explanation.append(ExplainedValueStep("HMAC input data of round %d" % (round_no), A + label + client_rnd + server_rnd))
			pms_to_ms_explanation.append(ExplainedValueStep("HMAC result of round %d" % (round_no), nextblock))

			hmac = Crypto.Hash.HMAC.new(digestmod = prf, key = premaster_secret)
			hmac.update(A)
			A = hmac.digest()
			pms_to_ms_explanation.append(ExplainedValueStep("Updated A value at end of round %d" % (round_no), A))
			round_no += 1
			pms_to_ms_explanation.append(ExplainedValueStep("", ""))
		master = bytes(master[:expect_len])
		
		pms_to_ms_explanation.append(ExplainedFunctionValueStep("output", "Master secret", master))
		if explain is not None:
			explain.append(pms_to_ms_explanation)
		return master
