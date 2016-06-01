# Simple-Cryptographic-APIs
This is the CryptoVerif input for the paper "Automated Security Proof of Simple Cryptographic APIs"
Before run the input "APIs.ocv", one must do the following changes in the build-in library "default.ocvl":
In the definition of define IND_CPA_INT_CTXT_sym_enc(keyseed, key, cleartext, ciphertext, seed, kgen, enc, dec, injbot, Z, Penc, Pencctxt), one has to modify the "fun Z(cleartext):cleartext" as "const Z:cleartext"
