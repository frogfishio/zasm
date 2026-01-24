# DEFECTS

Enter your defects here - [sev] desc

- [sev2] `zem --emit-cert` proof checking is brittle across tool versions.
	- Symptoms: `carcara check` may print "holey" (incomplete proof with `:rule hole`), or fail hard on `rare_rewrite`/`evaluate` steps depending on `cvc5 --proof-granularity`.
	- Impact: End-to-end proof verification cannot be used as a reliable gate; it was removed from `make test-validation` and proof-runner test is now opt-in (`ZEM_ENABLE_PROOF_TEST=1`).
	- Desired fix: either pin a known-good (cvc5, carcara) pair + flags that yield fully checkable Alethe proofs, or switch to a different proof format/checker pipeline.

