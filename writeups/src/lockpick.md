# Lockpick

**Event:** SolarCTF
**Category:** misc
**Flag:** `SOLARCTF{5pl1t_l0ck_g0es_brr}`

---

**Flag:** `SOLARCTF{5pl1t_l0ck_g0es_brr}`
**Artifact:** `lockpick.bin` - 32 220-byte Lattice **iCE40 HX1K** bitstream
**Author:** `z4vr1k_official`
**Prompt:** *"A bitstream device requiring a 32-bit unlock key has been intercepted."*

---

## TL;DR

1. `iceunpack` + `icebox_vlog` turn the bitstream into a gate-level netlist: **417 LUT, 105 FF,
   78 CARRY, one `SB_RAM40_4K`** in 512×8 mode, 35 inputs / 15 outputs.
2. The device is a **keystream generator**: 32 key pins in, an 8-bit data bus out (one byte
   every 2 clocks). A 256-byte block RAM is XORed into the bus during a 26-clock burst once
   per **59-clock period**.
3. There *is* a hard-coded 32-bit comparator (`io_2_0_1`), unique key in 2³² = `0x308a653c` -
   but the key is **not** the flag. The flag format for this event is a leet phrase
   (`SOLARCTF{NGC_n3v3r_sl33ps_0nl1n3}`), and hours went into pin-order permutations of that
   hex before that sank in.
4. **The flag is what the device prints.** With the correct key the output stream *is*
   `SOLARCTF{5pl1t_l0ck_g0es_brr}`, emitted once per period.
5. The one genuine unknown is the **data-bus bit order** - the author's `.pcf` is not in the
   bitstream - and it is *derivable*, because the author XORs the ROM byte into the keystream
   byte bitwise: ROM byte bit *i* must leave the chip on the same pin as design bit *i*.
6. With that pinned down, **exactly 1 of the 40 320 bit orders** makes the stream contain the
   literal `SOLARCTF{` → `perm = (7,4,5,0,6,3,1,2)` → flag.

---

## 1. From bitstream to netlist

```bash
git clone --depth 1 https://github.com/YosysHQ/icestorm.git ~/tools/icestorm
cd ~/tools/icestorm && make -j16                       # icepack / iceunpack / icebox
icebox/iceunpack lockpick.bin /tmp/lp.asc              # NOT the -c variant
cd icebox && python3 icebox_vlog.py -n lockpick /tmp/lp.asc > lockpick.v
```

`icebox_vlog.py` needs a one-line patch to read the in-tree `chipdb-1k.txt`, and `iceunpack`
must be run **without** `-c`, or the routing is dropped and the netlist is empty.

Inventory of `lockpick.v`: 417 LUTs, 105 flip-flops, 78 CARRY cells, one `SB_RAM40_4K`;
35 inputs - 32 key pins plus clock `io_6_0_1`, reset `io_0_8_0`, run `io_5_17_1` - and 15
outputs: the 8 data pins `io_0_3_0 io_0_2_0 io_0_2_1 io_2_0_0 io_3_0_0 io_4_0_0 io_4_0_1
io_5_17_0`, a 4-bit counter, a ready flag, and `io_2_0_1`.

## 2. What the device does

Protocol: reset (`io_0_8_0`) held high for 2 clocks, then `io_5_17_1` = 1. The data bus
updates **one byte every 2 clocks**. Per **59-clock period** the design runs a 26-clock
RAM burst (cycles 20…45, then 79…104, 138…163, …) and the 13 bytes emitted inside that burst
are

    bus[m] = keystream(key)[m] XOR P(rom_byte)

where `P` is a fixed bit permutation of the ROM byte onto the bus pins. Outside the burst the
byte is pure keystream. The keystream depends only on the key: there is no ROM feedback into
the state, and the read addresses do not depend on the key.

Measured with `sim.py` (our model of the netlist - see §5 for why it was wrong twice):

* period **59 clocks**; burst = 26 clocks = **13 emitted bytes**
* the injection constant is key-independent:
  `C = 14 13 3c a0 2a 8d 6f c4 45 93 23 78 d8`
* the ROM words read are the same for every key, e.g. word 36 alone shifts the output on
  10 cycles of the burst, word 34 and word 37 likewise; an unread word such as 200 changes
  nothing.

## 3. The trap: the `io_2_0_1` comparator

Of the 105 flip-flops exactly one - `io_2_0_1` - has a D-cone that touches the 32 key pins and
**nothing else**: no other state, no ROM, no control pin. It is a `key == CONST` built from
XOR/XNOR/AND LUTs, and SAT shows the constant is a **single minterm**: exactly one key value
in 2³² makes the pin high.

| check | command | result |
|---|---|---|
| SAT for a key that raises the pin | `satpin.py io_2_0_1` | **SAT - key = 0x308a653c** |
| is it unique? | `satpin.py io_2_0_1 --excl 308a653c` | **UNSAT** ⇒ one key in 2³² |
| does it fire in simulation? | `runkey.py 308a653c` | pin goes 1 at cycle 4, stays 1 |
| false positives? | `pinrate.py` | 0/200 random keys, 0 for key 0/1/all-ones |

So the device really does take a 32-bit key, and there is exactly one. The tempting answer is
`SOLARCTF{308a653c}` - and it is wrong. Two reasons to distrust it, in order of how long they
took to appreciate:

* this event's flags are **leet phrases** (`SOLARCTF{NGC_n3v3r_sl33ps_0nl1n3}`), not hex blobs;
* the comparator hands you the *key*, not the *payload*. A lock does not contain its own
  combination as text.

Before concluding that, we burned a long time on the pin→bit order (the comparator fixes the
value of every pin, but the ordering that turns 32 pin values into a 32-bit number lives in
the author's missing `.pcf`). 28 plausible orderings were scanned; none spells a word or a
memorable constant, which is itself the tell: if the author had wanted a hex flag, they would
have made the number recognisable.

## 4. Recovering the flag: the output stream, and its bit order

Simulate the netlist with the key and dump the bus. The naive dump looks like noise, because
my pin order for the data byte is an arbitrary reading of the netlist. Deriving the real order
is the whole trick:

1. The author's Verilog XORs the two operands **bitwise** - `data <= rom_byte ^ ks_byte` - so
   design bit *i* of the ROM byte and design bit *i* of the keystream byte must leave the chip
   on the **same pin**, and the pin order for the ROM byte therefore *is* the pin order for the
   data byte.
2. ROM byte bit *i* is `RDATA[2i]` - hardware-defined, not an authorial choice. So toggle ROM
   byte bit *i* and observe which bus pin moves. On a **zero-ROM baseline** (keystream zero)
   the pin that moves *is* design bit *i*.
3. Measuring all eight gives the order up to a small residual ambiguity. The flag removes it:
   render the burst under each of the 40 320 bit orders and demand the literal `SOLARCTF{`.
   **Exactly one order qualifies:**

       perm = (7, 4, 5, 0, 6, 3, 1, 2)

The stream then reads

    SOLARCTF{5pl1t_l0ck_g0es_brr}}SOLARCTF{5pl1t_l0ck_g0es_brr}SOLARCTF{...

The doubled `}` is not a typo - it is the byte-cadence phase drift: 59 clocks is odd, so
successive bursts land on alternating clock parity and consecutive copies of the flag are 29 or
30 emitted bytes apart (measured gaps: 30, 29, 30, 29, …).

A cross-check that ties the two halves of the story together: the 13 ROM-patched slots decode
to `{5pl1t_l0ck_g` - which is exactly `flag[8:21]`. So the author let the keystream carry the
first 8 and last 8 characters of the flag and patched the **middle** through the block RAM.
(The map key→keystream is affine, so a key matching a fixed text can be *solved* for, not
searched; the key that produces the flag is the same `0x308a653c` the comparator wants.)

**Flag: `SOLARCTF{5pl1t_l0ck_g0es_brr}`**

## 5. The two simulator bugs that made this hard

To have ground truth we wrote `sim.py`, a gate-level simulator for `lockpick.v`. It was wrong
twice, in the same peripheral, and both bugs sent the investigation the wrong way.

**Bug 1 - RAM read-mode bit order.** `icebox_vlog` prints the RAM's `.RDATA` port MSB-first, so
parsed index *j* is `RDATA[15-j]`. The first model wrote `(word >> (j + half)) & 1` at even *j*,
i.e. onto the *unconnected* `open_*` RDATA pins, leaving the eight connected nets permanently
zero - **no ROM bit ever reached the netlist**. The conclusion drawn from that ("the 256-byte
RAM is a decoy") was an artifact of the model, not a property of the design.

**Bug 2 - lane selector.** The fix put data on the right pins but inverted the lane. The
correct semantics, taken from Yosys `share/ice40/cells_sim.v` (READ_MODE=1):

    RMASK   = RADDR[8]==0 ? 16'hAAAA : 16'h5555
    RDATA_I = memory[RADDR[7:0]] & ~RMASK      # lane 0 keeps the EVEN bits
    RDATA   = {1'b0,|RDATA_I[15:14], 1'b0,|RDATA_I[13:12], ...}   # byte on the even pins
    ⇒ byte bit i = memory[addr & 255][2i + RADDR[8]]

Both bugs were caught the same way: writing an *independent* implementation of those
`cells_sim.v` rules and diffing it against `sim.py` across hundreds of addresses, including the
addresses the design actually reads. Only then was the fix a derivation rather than a guess -
and only then did the ROM's real role (patching the middle of the flag) become visible.

## 6. Verification

The solve and verification scripts:

* `python3 solve_flag.py` - walks all 40 320 bit orders, prints the single one containing
  `SOLARCTF{` (`perm = (7,4,5,0,6,3,1,2)`, offset 0) and the flag.
* `python3 verify_flag.py`, `python3 verify_flag2.py` - the flag sits at offset 0; every
  complete occurrence equals `SOLARCTF{5pl1t_l0ck_g0es_brr}`; gaps ∈ {29,30}; the ROM-patched
  slots decode to `flag[8:21]`; and a negative control (identity bit order) produces neither the
  prefix nor the flag.
* `python3 satpin.py io_2_0_1` → `SAT key = 0x308a653c`;
  `python3 satpin.py io_2_0_1 --excl 308a653c` → `UNSAT` (uniqueness of the key).

## 7. Pitfalls worth remembering

* `iceunpack` **without** `-c`; `icebox_vlog` needs the in-tree `chipdb-1k.txt`.
* Yosys `sat` cannot ingest `icebox_vlog`'s async-reset FFs as-is - use `-seq` /
  `-set-init-zero`; select one top module and `flatten` first; make the observed signal a
  **port**, or `opt_clean` deletes the design ("Imported 0 cells").
* A hand-written gate-level simulator is only as good as its primitive models. Diff them
  against the vendor/Yosys model *before* trusting any negative result - both of our bugs
  produced confident, false "the ROM doesn't matter" conclusions.
* If a SAT harness encodes a temporal assumption ("the shift register is filled by step *t*"),
  gate it explicitly: an ungated version will happily satisfy your constraint on an unfilled
  register and hand you a bogus model.
* When the artifact is a *device*, ask what it **emits**, not only what it **contains**. The
  comparator was real, unique and solvable - and completely irrelevant to the flag.
