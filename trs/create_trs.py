#!/usr/bin/python3

# This is a sample script to create or extend Riscure TRS files, using
# the python library provided by Riscure.
#
# The trsfile package can be either found at its github page:
#   https://github.com/Riscure/python-trsfile
# and in the pip3 installer:
#   pip3 install trsfile

import random, os, trsfile
from trsfile import trs_open, Trace, SampleCoding, TracePadding, Header

with trs_open(
		'trace-set.trs',                 # File name of the trace set
		'w',                             # Mode: r, w, x, a (default to x)
		# Zero or more options can be passed (supported options depend on the storage engine)
		engine = 'TrsEngine',            # Optional: how the trace set is stored (defaults to TrsEngine)
		headers = {                      # Optional: headers (see Header class)
			Header.LABEL_X: 'Testing X',
			Header.LABEL_Y: 'Testing Y',
			Header.DESCRIPTION: 'Testing trace creation',
		},
		padding_mode = TracePadding.AUTO,# Optional: padding mode (defaults to TracePadding.AUTO)
		live_update = True               # Optional: updates the TRS file for live preview (small performance hit)
		                                 #   0 (False): Disabled (default)
		                                 #   1 (True) : TRS file updated after every trace
		                                 #   N        : TRS file is updated after N traces
	) as trs_file:
	# Extend the trace file with 100 traces with each 1000 samples
#	trs_file.extend([
#		Trace(
#			SampleCoding.FLOAT,
#			[random.uniform(-255, 255) for _ in range(0, 1000)],
#			data = os.urandom(16)
#		)
#		for _ in range(0, 100)]
#	)

	# Replace 5 traces (the slice [0:10:2]) with random length traces.
	# Because we are creating using the TracePadding.PAD mode, all traces
	# will be clipped or padded on the first trace length
#	trs_file[0:10:2] = [
#		Trace(
#			SampleCoding.FLOAT,
#			[random.uniform(0, 255) for _ in range(0, random.randrange(1000))],
#			data = os.urandom(16),
#			title = 'Clipped trace'
#		)
#		for _ in range(0, 5)
#	]

	# Adding one Trace
#	trs_file.append(
#		Trace(
#			SampleCoding.FLOAT,
#			[random.uniform(-255, 255) for _ in range(0, 1000)],
#			data = os.urandom(16)
#		)
#	)

	# Adding one Trace
	#trs_file.append(
	trs_file.extend(
		Trace(
			SampleCoding.INT,
			[1, 10],
#			data = os.urandom(16),
#                        data = b"\x91+\x98'Q\xfaw\xe4\xbcM;!\x0e\xb5\xaf\xca",
			title = 'INTEIRO'
		)
	)

        
        # We cannot delete traces with the TrsEngine, other engines do support this feature
	#del trs_file[40:50]

	# We can only change headers with a value that has the same length as the previous value
	# with the TrsEngine, other engines can support dynamically adding, deleting or changing
	# headers.
	#trs_file.update_header(Header.LABEL_X, 'Time')
	#trs_file.update_header(Header.LABEL_Y, 'Voltage')
	#trs_file.update_header(Header.DESCRIPTION, 'Traces created for some purpose!')

	print('Total length of new trace set: {0:d}'.format(len(trs_file)))
