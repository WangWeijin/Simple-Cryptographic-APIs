# Simple-Cryptographic-APIs
This is the CryptoVerif input for the paper "Automated Security Proof of Simple Cryptographic APIs"
Before run the input "APIs.ocv", one must do the following changes in the build-in library "default.ocvl":
In the definition of define IND_CPA_INT_CTXT_sym_enc(keyseed, key, cleartext, ciphertext, seed, kgen, enc, dec, injbot, Z, Penc, Pencctxt), one has to modify the "fun Z(cleartext):cleartext" as "const Z:cleartext", as follows

define IND_CPA_INT_CTXT_sym_enc(keyseed, key, cleartext, ciphertext, seed, kgen, enc, dec, injbot, Z, Penc, Pencctxt) { 

param N, N2, N3.

fun enc(cleartext, key, seed): ciphertext.
fun kgen(keyseed):key.
fun dec(ciphertext, key): bitstringbot.

fun enc2(cleartext, key, seed): ciphertext.
fun kgen2(keyseed):key.

fun injbot(cleartext):bitstringbot [compos].
forall x:cleartext; injbot(x) <> bottom.

(* The function Z returns for each bitstring, a bitstring
   of the same length, consisting only of zeroes. *)
const Z:cleartext.

forall m:cleartext, r:keyseed, r2:seed; 
	dec(enc(m, kgen(r), r2), kgen(r)) = injbot(m).

	(* IND-CPA *)

equiv ind_cpa(enc)
       foreach i2 <= N2 do r <-R keyseed; 
       	       foreach i <= N do r2 <-R seed; Oenc(x:cleartext) := 
	       	       return(enc(x, kgen2(r), r2))
     <=(N2 * Penc(time + (N2-1)*(time(kgen) + N*time(enc, maxlength(x))), N, maxlength(x)))=> 
       foreach i2 <= N2 do r <-R keyseed; 
       	       foreach i <= N do r2 <-R seed; Oenc(x:cleartext) := 
	       	       return(enc2(Z, kgen2(r), r2)).

	(* INT-CTXT *)

equiv int_ctxt(enc)
      foreach i2 <= N2 do r <-R keyseed; (
      	      foreach i <= N do r2 <-R seed; Oenc(x:cleartext) := return(enc(x, kgen(r), r2)) |
	      foreach i3 <= N3 do Odec(y:ciphertext) := return(dec(y,kgen(r))))
     <=(N2 * Pencctxt(time + (N2-1)*(time(kgen) + N*time(enc, maxlength(x)) + N3*time(dec,maxlength(y))), N, N3, maxlength(x), maxlength(y)))=> [computational] 
      foreach i2 <= N2 do r <-R keyseed [unchanged]; (
      	      foreach i <= N do r2 <-R seed [unchanged]; Oenc(x:cleartext) := z:ciphertext <- enc(x, kgen2(r), r2); return(z) |
	      foreach i3 <= N3 do Odec(y:ciphertext) := find j <= N suchthat defined(x[j],r2[j],z[j]) && z[j] = y then return(injbot(x[j])) else return(bottom)).

}
