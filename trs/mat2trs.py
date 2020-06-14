#!/usr/bin/python3

# This script reads Matlab MAT files, each one containing a power trace,
# and saves it as a Riscure TRS file, all traces in one file.

# Include library to manipulate Matlab MAT files.
# Documentation can be found at:
# https://scipy-cookbook.readthedocs.io/items/Reading_mat_files.html
from scipy.io import loadmat

# Include library to manipulate Riscure TRS files.
import os, trsfile
from trsfile import trs_open, Trace, SampleCoding, TracePadding, Header

#https://docs.python.org/3/library/binascii.html
import binascii

# Include library to debug python scripts.
# Documentation can be found at:
# https://docs.python.org/3/library/pdb.html
import pdb                      # for python debugging. Continue with 'c'

# Change the path below to point to the folder containing the power traces
INCOMING_FOLDER='2019-03-1ktraces_mat'
OUTCOMING_FOLDER='2019-03-1ktraces_mat_processed'
TRS_FILENAME='trace-set.trs'

# This code expects that the incoming folder contains one file per trace, saved as MAT file, and that
# its name contains the key, plaintext and ciphertext used, in this manner:
# trace_DES__k=f49d7b07c3ee29ef_m=004c5517a01903c7_c=c2eb8188c1e11cd6.mat
traces_filename=OUTCOMING_FOLDER+'/'+TRS_FILENAME+'.traces'
input_filename=OUTCOMING_FOLDER+'/'+TRS_FILENAME+'.input'
config_filename=OUTCOMING_FOLDER+'/'+TRS_FILENAME+'.config'

# indicates that the data are float numbers
isfloat=1
ntraces=0
nsamples=0

os.system('mkdir '+OUTCOMING_FOLDER)

traces = open(traces_filename, 'ab')
tracename_file=open(input_filename, 'ab')


trs_file = trs_open(
    OUTCOMING_FOLDER+'/'+TRS_FILENAME,                 # File name of the trace set
    'w',                             # Mode: r, w, x, a (default to x)
    # Zero or more options can be passed (supported options depend on the storage engine)
    #engine = 'TrsEngine',            # Optional: how the trace set is stored (defaults to TrsEngine)
    #headers = {                      # Optional: headers (see Header class)
    #	Header.LABEL_X: 'Testing X',
    #	Header.LABEL_Y: 'Testing Y',
    #	Header.DESCRIPTION: 'Testing trace creation',
    #},
    padding_mode = TracePadding.AUTO,# Optional: padding mode (defaults to TracePadding.AUTO)
    live_update = True               # Optional: updates the TRS file for live preview (small performance hit)
                                 #   0 (False): Disabled (default)
                                 #   1 (True) : TRS file updated after every trace
                                 #   N        : TRS file is updated after N traces
    )


# loop over all files from incoming folder
for filename in os.listdir(INCOMING_FOLDER):

    if not filename.endswith(".mat"):
        print('  skipping '+filename)
        # print(os.path.join(directory, filename))
        continue

    #print('processing '+filename)

    # filename is the file getting renamed, pre is the part of file name before extension and ext is current extension
    pre, ext = os.path.splitext(filename)
    OUTPUT_NAME=pre+'.mat'

    # reading matlab files in python, using scipy:
    # https://docs.scipy.org/doc/scipy/reference/tutorial/io.html
    matfile = loadmat(INCOMING_FOLDER+'/'+filename)

    # this code returns a NUMPY ndarray:
    # https://docs.scipy.org/doc/numpy/reference/generated/numpy.ndarray.html
    trace = matfile['trace'].tobytes()

    #print(' trace contains:')
    #print(trace)

    # saves data as TRS file
    trs_file.append(

            Trace(
       	        SampleCoding.FLOAT,
                trace,
		data = os.urandom(16),
                #data = b"\x91+\x98'Q\xfaw\xe4\xbcM;!\x0e\xb5\xaf\xca",
                title = filename
            )
    )

    # parses filename separating ciphertext (c), plaintext (m) and key (k)
    init_pos=filename.find('k=')
    key=filename[init_pos+2:init_pos+18]

    init_pos=filename.find('m=')
    message=filename[init_pos+2:init_pos+18]

    init_pos=filename.find('c=')
    ciphertext=filename[init_pos+2:init_pos+18]

    print('writing '+message)
    tracename_file.write(binascii.a2b_hex(message))
    traces.write(trace)

    # ensures we write the data
    tracename_file.flush
    traces.flush()

    # updates data to write to config
    ntraces +=1
    nsamples = len(trace)
    print('ok')

    #pdb.set_trace() # for debug. continue with 'c'

    print('file read successfully')

    # display a message each 100 traces processed
    if ntraces % 100 == 0 or ntraces < 10:
        print(' '+str(ntraces)+' traces processed !')

# writing config file, for Daredevil
#
# guess is 8 for DES, 16 for AES
# guess={input_filename} {ntraces} 8

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
guess={input_filename} {ntraces} 8

[General]
threads=8
order=1
return_type=double
algorithm=AES
position=LUT/DES_BEFORE_SBOX
round=0
bitnum=none
bytenum=all
#correct_key=0x000102030405060708090a0b0c0d0e0f
memory=4G
top=20
""".format(format=["i", "f"][isfloat], ntraces=ntraces, nsamples=nsamples, traces_filename=traces_filename, input_filename=input_filename))


