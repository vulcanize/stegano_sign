This demo:
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

(Not sure if Steganography is any better than a fix-location embedding but we will hide the key location to start.)
