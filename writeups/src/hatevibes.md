# HateVibes

**Event:** October 2026 SkillBit Flash CTF
**Category:** forensics
**Flag:** `MetaCTF{East_or_West_h0m3_1S_b3st}`

---


## 1. Recon

`hatevibe.zip` contains `Joint-Declaration-C5+GER_final.doc` - an OOXML Word document
dressed up as a diplomatic engagement statement. Unzip it (`unzip -o file.doc -d ex/`)
and the macro project is visible at `ex/word/vbaProject.bin`.

## 2. Stage 1 - the macro (`vbaProject.bin`)

The `AutoExec` routine is `documeNt_opEn` (mis-cased to dodge naive string scans). On open
it:

1. Writes `HKCU\Software\Microsoft\Office\<ver>\Word\Security\AccessVBOM = 1`
   (grants programmatic access to the VBA project object model).
2. Unprotects the document with the hardcoded password `oikmseM#*inmowefj8349an3`.
3. Burns time to outlast sandboxes: `While Now < sss + TimeValue("20:20:20") ...`.
4. Copies the document's Variables into a throwaway doc, injects `block1` / `block2` / `s2`
   as new VBA, saves it to `%LOCALAPPDATA%\Temp\<name>.doc` and re-opens it (`rundoc`).

`strings -n 6 vbaProject.bin` confirms `documeNt_opEn`, `oikmseM#*inmowefj8349an3`, `20:20:20`.

## 3. Stage 2 - payload hidden in document variables

`word/settings.xml` holds **69** `<w:docVar>` entries (numeric prefix 1001..1025 plus a
random suffix; sort by the numeric prefix). Each `w:val` is a hex chunk; concatenated and
hex-decoded they form an **HTA** (Application ID `setuptools`):

```
NAME="setuptools" WINDOWSTATE="minimize" ... <span id=codeblock>load</span><script Language=...
```

`block1` VBA writes those variables out as `Chr(&Hxx)` pairs to
`%LOCALAPPDATA%\Settings\locale`. `block2` VBA registers a hidden scheduled task
`\Settings\ServiceDispatch` (`repeat PT4M`) that runs `mshta.exe` on that `locale` file.
`s2` chains the two (`AddFromString(block1)`, `AddFromString(block2)`, `goods : baads`).

## 4. Stage 3 - the HTA (`VBScript.Encode`)

The HTA body is `VBScript.Encode`d (`encoded.vbe`). Decode it (Didier Stevens' decoder,
ported to Python 3 - read the file as **latin-1**). The decoded script's `temp()` rebuilds
a hex blob and XORs it with the literal key `dGgzLXMzY3IzdC1rZXk=` into
`codeblock.InnerHTML`:

```vb
str = ""
For j = 0 To Len(text)-1
  str = str & Chr(Asc(Mid(text,j+1,1)) Xor Asc(Mid("dGgzLXMzY3IzdC1rZXk=",(j Mod Len("dGgzLXMzY3IzdC1rZXk=")+1),1)))
Next
codeblock.InnerHTML = str
```

## 5. Stage 4 - the final beacon (the flag)

The deobfuscated VBScript beacons out: **HTTP PUT JSON** to
`https://metactf.com/setup.php`, `User-Agent = "<ComputerName> <UserName>"`, expecting a
response prefixed `sd5ddf3e3fg4gfds` and decoding it with the same `temp()` routine.
Additional endpoints referenced: `/upset.php`, `/local.php`.

The flag is hardcoded in that stage:

```
asxcaw = "MetaCTF{East_or_West_h0m3_1S_b3st}"
```

## 6. IOCs

- `%LOCALAPPDATA%\Settings\locale` (dropped HTA)
- Scheduled task `\Settings\ServiceDispatch` (`PT4M`, runs `mshta.exe`)
- `mshta.exe` HTTP PUT to `metactf.com/setup.php` | `/upset.php` | `/local.php`
- Response magic tag `sd5ddf3e3fg4gfds`
- Document protection password `oikmseM#*inmowefj8349an3`

## 7. Flag

```
MetaCTF{East_or_West_h0m3_1S_b3st}
```
