#!/usr/bin/env python

# Little helper to convert Riscure TRS format to Daredevil format.
# Samples are copied raw, so make sure to configure properly Daredevil.
# Currently it's assuming AES traces, tune it to your needs.

import os
import sys
import glob
import struct
import binascii

trs_filename=sys.argv[1]
traces_filename=trs_filename+'.traces'
input_filename=trs_filename+'.input'
output_filename=trs_filename+'.output'
config_filename=trs_filename+'.config'

with open(trs_filename, 'rb') as trs:
    while True:
        tag, length = struct.unpack('BB', trs.read(2))
        rawval = trs.read(length)
        print("Parsing tag 0x%02X of length %i: %s" % (tag, length, binascii.hexlify(rawval)))
        if tag == 0x41: # Nb traces
            assert length == 4
            ntraces, = struct.unpack('<I', rawval)
            print("Number of traces: %i" % ntraces)
            continue
        if tag == 0x42: # Nb samples
            assert length == 4
            nsamples,=struct.unpack('<I', rawval)
            print("Number of samples per trace: %i" % nsamples)
            continue
        if tag == 0x43: # sample format
            assert length == 1
            val, = struct.unpack('B', rawval)
            isfloat = val >> 4
            samplesize = val & 0xf
            assert isfloat in [0, 1]
            assert samplesize in [1, 2, 4]
            print("Sample format: %s coded on %i bytes" % (["integer", "float"][isfloat], samplesize))
            continue
        if tag == 0x44: # data size
            assert length == 2
            datasize, = struct.unpack('<H', rawval)
            assert datasize in [16, 32]
            print("Data size: %i bytes" % datasize)
            continue
        if tag == 0x5f: # end-of-header
            assert length == 0
            break
    with open(traces_filename, 'wb') as traces, open(input_filename, 'wb') as input, open(output_filename, 'wb') as output:
        for i in range(ntraces):
            data_in=trs.read(16)
            if datasize == 32:
                data_out=trs.read(16)
            input.write(data_in)
            output.write(data_out)
            traces.write(trs.read(nsamples * samplesize))
    with open(config_filename, 'w') as config:
        config.write(
"""
[Traces]
files=1
trace_type={format}
transpose=true
index=0
nsamples={nsamples}
trace={traces_filename} {ntraces} {nsamples}

[Guesses]
files=1
guess_type=u
transpose=true
guess={input_filename} {ntraces} 16

[General]
threads=8
order=1
return_type=double
algorithm=AES
position=LUT/AES_AFTER_SBOX
round=0
bitnum=none
bytenum=all
#correct_key=0x000102030405060708090a0b0c0d0e0f
memory=4G
top=20
""".format(format=["i", "f"][isfloat], ntraces=ntraces, nsamples=nsamples, traces_filename=traces_filename, input_filename=input_filename))
