# Cairn

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{w41k_th3_sup3rs1n9u14r_l46yr1ntH}`

---

**Flag: `hiCTF{w41k_th3_sup3rs1n9u14r_l46yr1ntH}`**

Runtime of the walk: 9,891 s (2 h 45 m) at 9.44 ms/step on one core; 1,048,576 steps.
Final state j_T = (2951744835154356679408485058539998725114852725772335444978399055687248892073,
76297261829986891261504719508868871098352200233656976244600190934732692176052)
key = SHA256(ser(j_T) || "IsogenyLabyrinth") = bf722c55d3a4656cd731699335706f1dab4ba16caf8c2a6bb45b1f949adbc5ca

## The challenge
Rule sheet `challenge files/RULES.md` (and the author's design source, SAC2021
"Verifiable Isogeny Walks: Towards an Isogeny-based Postquantum VDF"):
p = 2^256-2^32-977, GF(p^2) = GF(p)[i]/(i^2+1), j0 = 1728, T = 2^20, L = [2,3,5,7].
Step i: h = SHA256(LE32(a)||LE32(b)||BE8(i)||salt); l = L[h[0] mod 4];
f_sq = squarefree part of Phi_l(j,Y); j := (h[1] mod n)-th smallest root of f_sq in GF(p^2).
Then key = SHA256(ser(j_T)||"IsogenyLabyrinth") and the flag is AES-256-GCM.

This is a VDF by construction: 2^20 *sequential* root extractions, and each state is a
fresh 512-bit field element, so there is no lookahead, no cycle and no reuse. "One step
at a time. Do not look back." is literal.

## Why naive solves are hopeless
Finding the roots of a degree-<=8 polynomial that splits over GF(p^2) by generic
factorisation costs 20-130 ms/step with PARI / NTL / FLINT / Sage (`f.roots()` /
`factor()`), i.e. 6-40 hours for 2^20 steps. Measured on this box: Sage 134 ms/step,
PARI factor 29 ms, PARI Mod(T,N)^p 10 ms, FLINT factor 7-13 ms, NTL CanZass 14 ms.

## The fast method: one exponentiation to p per step
1. `N = f*conj(f)` in GF(p)[Y] is just `(Re f)^2 + (Im f)^2` (no GF(p^2) arithmetic
   needed). Its roots are the roots of f and their conjugates, so every irreducible
   factor of `Nsf = radical(N)` has degree 1 or 2.
2. `A = Y^p mod Nsf` - the whole cost of the step (256 squarings of deg-<=16 polys).
3. `G1 = gcd(Nsf, A-Y)` are the F_p-rational factors; `H1 = Nsf/G1` is a product of
   distinct irreducible quadratics `Y^2 - t_j Y + n_j`, because Y^p == conj(z) ==
   t_j - Y in the component of a conjugate pair.
4. `T = A + Y mod H1` is therefore F_p-valued with value `t_j` in component j. Its
   values (the traces) are the roots of a degree-m (m <= 8) polynomial Psi over F_p,
   recovered with Newton's identities from `sum_j t_j^k = Tr_{alg}(T^k)/2`, where Tr
   is the trace of multiplication-by-x on F_p[Y]/H1 (an m x m matrix, cheap).
5. Split H1 by `gcd(H1, T - t)` for each root t of Psi (roots of a split poly over
   F_p by Cantor-Zassenhaus/EDF with one small pow_mod per level).
6. Roots of `Y^2 - tY + n` are `(t +- sqrt(t^2-4n))/2`. Every element of F_p is a
   square in GF(p^2), and `s = disc^((p+1)/4)` gives `s^2 = +disc` (QR, sqrt is s) or
   `-disc` (non-QR, sqrt is s*i) - exactly one exponentiation, no Legendre test.
7. Keep the candidates with `f(candidate) == 0` (this discards the conjugate roots),
   sort by (a,b) as unsigned 256-bit pairs, take index `h[1] mod n`.

Two further savings, both exact:
* The previous vertex is a root of Phi_l(j,.) only when the degree did not change
  (the supplied Phi_l are not symmetric in X,Y - verified - so the backward edge
  exists only for the same l). It is deflated out whenever `Phi_l(j,j_prev) == 0`,
  which cuts the modulus degree by 2 for ~25% of steps.
* f_sq is only recomputed (via gcd(f,f')) when the number of distinct roots found
  differs from deg f; normally f is already squarefree.

## Verification
* Root sets per step identical to an independent Sage implementation
  (`ref_roots.py`) for the first 25 steps, with and without the deflation path -
  `diff` clean. That cross-checks norm/radical/Frobenius/trace-Newton/quadratic
  extraction end to end.
* 143 returned roots over 30 steps: each satisfies `f_sq(root) = 0`, count equals
  deg f_sq and the number of distinct roots, list is sorted.
* The final flag is gated by the AES-GCM tag: a wrong j_T cannot produce a flag.
  It was re-derived and decrypted with a second library (python `cryptography`
  AESGCM) as well as pycryptodome, same plaintext, format `hiCTF{...}`.
* The walk ran 1,048,576 steps with no assertion failure (the solver raises rather
  than continuing on any internal inconsistency).

## Pitfalls worth remembering
* cypari2 has no `deriv`; `pari.Polrev` vs `pari.Pol` (ascending vs descending) and
  PARI `factor` over a modulus needs the `Mod(1,p)` factor or it factors over Z.
* FLINT `fmpz_mod_poly` gcd/divmod/radical/pow_mod/factor are the useful entry
  points from python (`python-flint`, installed for the system python3.14).
* The `Re/Im`-gcd shortcut ("F_p-rational roots = gcd(Re f, Im f)") is WRONG in
  general: fsq(z)=0 gives Re(z) = -i*Im(z), not Re(z)=Im(z)=0. The norm-based route
  (`radical(f*conj(f))`) is the correct one.
