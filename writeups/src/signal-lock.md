# Signal Lock

**Event:** HICyberCon CTF 2026
**Category:** rev
**Flag:** `hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}`

---

**Category:** Reverse engineering (Erlang/BEAM) · `signal-lock.zip` →
`signal_lock.beam` (sha256 `93651d91…`)

## Artifact
A stripped, compiled **BEAM module** `signal_lock` with a single entry point
`verify/1`. Per the brief it validates a client's session-integrity token; a
correct token returns `{ok, <<"hiCTF{...}">>}`.

## Method
`abstract_code` is absent, so disassemble the BEAM and read the SSA:

```erlang
%% erl -pa . -eval 'io:format("~p~n",[beam_disasm:file("signal_lock.beam")]),halt().'
```

`verify/1` does, in order:
1. `is_binary(Token)` and `byte_size(Token) == 8` (exactly 8 bytes);
2. `bs_match` an **unsigned 64-bit big-endian** integer out of the token;
3. `transform(Int) == 12675316763487955908` (`0xAFE7C5708F40EBC4`);
4. on match, `unlock(Int)` returns `{ok, <<Flag/binary>>}`.

`transform/1` (from the disasm) spreads and mixes the 64-bit value with
multiply/rotate/add constants modulo `2^64`:

```
x = (x * 0x9E3779B97F4A7C15) band 0xFFFFFFFFFFFFFFFF   ; golden-ratio spread
x = rotl(x, 29)                                          ; 64-bit rotate left
x = (x + 0x0123456789ABCDEF) band 0xFFFFFFFFFFFFFFFF
```

Working this chain backwards pins the one 8-byte token that satisfies the
comparison:

```
token = "g4m30v3r"
```

(confirmed by executing the module - see Verification; the module itself is the
authority on whether the token is accepted.)

## Repro
```bash
# Erlang/OTP 26+ required (older runtimes reject the module's opcodes)
erl -pa . \
  -eval 'io:format("~p~n",[signal_lock:verify(<<"g4m30v3r">>)]), halt().'
```
Output:
```
{ok,<<"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}">>}
```

## Verification
The strongest possible oracle: **the challenge's own unmodified module** returns
the flag for the candidate token - the token is accepted by
`signal_lock:verify/1`, not merely "plausible". No brute force was used; the
token was derived from the arithmetic in `transform/1`.

## Tooling notes
- This is a **compiled** `.beam` (no debug info); use `beam_disasm:file/1`, not
  `beam_lib:chunks(...,[abstract_code])`.
- The module is gzip-compressed BEAM (`gzip compressed data, original size 1624`).
