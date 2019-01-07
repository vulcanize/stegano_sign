#!/usr/bin/env python

# from secrets import token_bytes
from eth_keys import keys
from PIL import Image
import requests
from baseconv import base16, base56
from stegano import lsbset
from stegano.lsbset import generators
import sha3

'''This demo:
1. generates a keypair
2. generates a message from ethereum block metadata
3. signs message with key
4. Steganographically encodes signature into image from disk
5. hashes vessel_img

The vessel_img should be kept private.
The vessel_img_hash can be aggregated and published to a blockchain.
Verification of identity happens off chain.
The published vessel_img hash can be attached to any message as
a loose claim of identity.

When verifing the identity:
1. verifier request image matching hash.
2. prover provides image
3. if image fails to satisfy verifier
    -verification stops
   else:
4.  -prover provides location of signature in image and message
5.  -verifier provides nonce
6.  -prover sends signed nonce
7. Verifier confirms the pubkey of signature and signed_nonce match.

At this point Verifier knows whatever it needs to know about Prover and cannot
impersonate Prover when given a new 5 because they will be unable to generate
the corresponding 6. Furthermore, if the verifier tampers with the image, it
will no longer match the published hash.

This protocol allows for the prover to add aditional security by encoding
multiple signatures into the same Vessel image. Using the naive techniques of
this demo thousands of sigs could be embedded in the sample vessel image.
BLS 1-of-n multisig would allow for many magnitudes more.
BPCS Steganography would allow for more still.
'''

# 1. Generate message signing key
#  tb = token_bytes(32)
tb = b'd\xe20\xf1)m%\x08\x9e[\x00\x0f\x9e\xdd\xc2Vf\xf9W\xf1]\xef\xdb\xaa\xc7\rD\xa5K\xd0\x1e,'
pk = keys.PrivateKey(tb)

# 2. Generate message
# base_url = 'https://api.blockcypher.com/v1/eth/main'
# latest_fin_eth_blk_num = int(requests.get(base_url).json()['height']) - 12
# r = requests.get(base_url + '/blocks/' + str(latest_fin_eth_blk_num)).json()
# msg = bytes(str(r['hash']) +'_'+ str(r['time']), 'utf-8')
msg = b'fe895898b8064515820af15e1921f8b5ae3c1660bb5dfd63bc07c04ce236972b_2018-12-16T17:36:36Z'

# 3. Sign msg with pk
sig = pk.sign_msg(msg)

# Stegano's jpg support is broken.
img = Image.open("sample.jpg")
img.save("sample.png")
del img

# 4. encode sig into img
# there has got to be an easier way...
secret_sig = base56.encode(base16.decode(sig.to_hex()[2:].upper()))
vessel_img = lsbset.hide("sample.png", secret_sig, generators.eratosthenes())
vessel_img.save("sig0.png")

# 5. Hash vessel_img
vih = sha3.keccak_256(vessel_img.tobytes()).digest()


'''VERIFICATION EXAMPLE'''
# 4. Prover provides verifer with secret_sig and generator used, verifer extracts secret_sig
revealed_sig = lsbset.reveal("sig0.png", generators.eratosthenes())
# "sanity" check
# base16.encode(base56.decode(revealed_sig)).lower() == sig.to_hex()[2:]

# Convert back into a eth_key Signature
rsig = keys.Signature(bytes.fromhex(base16.encode(base56.decode(revealed_sig))))

# 5. Verifier provides nonce
nonce = b'717f4e012baa4450ccdff3477a5c652bc55f224a054712d46e60aa05022aeac3_2018-12-16T19:30:41Z'

# 6. Prover provides signed nonce to Verifier (and message ws sent at some point)
signed_nonce = pk.sign_msg(nonce)

# 7. Verifer confirms sigs match
signed_nonce.recover_public_key_from_msg(nonce) == rsig.recover_public_key_from_msg(msg)

import os
os.remove("sig0.png")
os.remove("sample.png")

