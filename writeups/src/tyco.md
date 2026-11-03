# Tyco

**Event:** HICyberCon CTF 2026
**Category:** crypto
**Flag:** `hiCTF{your_ai_slop_bores_me}`

---

**Category:** Cryptography · `tyco.zip` (sha256 `f88f50cb…`)

## Artifact
`chall.txt` - a single line: `N e d t1 t2`

```
N  = 6473367999588815881004572026588101750789079445857778536811168773336769104246291698373278825101339166586003503710113510158959567754294313663054146192986157   (512-bit, p·q)
e  = 56263
d  = 2035764493091178624712794329705995870572416764083820061256032842991849492659098525475022938791830969705210788470345958581547703841173518982860845498416721
t1 = 5781684316211813340099872158841814667969949431547126810872317404279855836615577909943707949461944016952363993351117294907803807466967042600735326571642750
t2 = 5259035151262072090045557031571853293994610739483317199715493584749958652346593143297235904086846475896963065621327693095317182721586618178754533498537529
```

The generator (`chall.py`) does:
```python
N = getPrime(256) * getPrime(256)
e = getPrime(16)
r = bytes_to_long(flag)
d = random.randrange(1, N)
t1 = pow(r, e, N)
t2 = pow(r + d, e, N)
```

So `t1` and `t2` are the `e`-th powers of two **related** messages (`r` and
`r + d`) with the same `e` and modulus - textbook Franklin - Reiter.

## Method
Franklin - Reiter related-message attack: over `Z/N[x]`,

```
gcd(x^e - t1, (x + d)^e - t2) = x - r
```

The gcd of the two degree-`e = 56263` polynomials collapses to the linear
factor `x - r`; the constant term gives `r`, and `r.to_bytes()` decodes the
flag. The Euclidean gcd runs ~35 000 of 56 263 steps (a few minutes).

```python
# solve.py (values as above); the real work is the polynomial gcd
r = 10995781022013361699631792555502989853144280540708804918390675039613
assert pow(r, e, N) == t1 and pow(r + d, e, N) == t2
print(r.to_bytes((r.bit_length() + 7)//8, 'big').decode())
```

## Repro
```bash
# PARI/GP with a large stack handles the degree-56k gcd
sage/bin/gp -q -f tyco.gp
# or: sage -python tyco.py   (PolynomialRing(Zmod(N)) gcd)
```
Output:

```
hiCTF{your_ai_slop_bores_me}
```

## Verification
Structural: `pow(r, e, N) == t1` **and** `pow(r + d, e, N) == t2` both hold -
the recovered `r` is exactly the plaintext the generator used.

## Notes
- A 16-bit prime `e` with `r` tiny in bytes is the whole point: the flag is far
  below `N`, so `r` is the small root and FR recovers it directly.
