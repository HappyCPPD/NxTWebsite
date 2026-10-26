# Unreal Duck

**Event:** SolarCTF
**Category:** rev
**Flag:** `SOLARCTF{unr34l_3ng1n3_p4th_f1nd1ng_0n_w1nd0ws}`

---

> Author: SD4RK · Task: `unreal_duck.zip` · Brief: *"This game hides something, but what?"*

**Flag:** `SOLARCTF{unr34l_3ng1n3_p4th_f1nd1ng_0n_w1nd0ws}`

The flag arrives as a handwritten image with the note "all lowercase".

---

## TL;DR

The zip holds a UE 5.7 Windows client for a multiplayer duck game. The client connects to a live
dedicated server. The server sends the flag (an image) to whoever completes the route. The route has
three trigger volumes, and the hidden part is that **inside each volume you have to type a secret
5‑letter code**. The client hashes the letters and the server checks them. I brute-forced the three
codes offline from constants in the binary: **ILOVE / DUCKS / ALOTT** ("I love ducks a lott").
Then I ran the client under Wine on Linux, drove the duck through the route with scripted
keypresses, typed the codes and got the payload.

---

## 1. Recon

The zip unpacks to a standard UE 5.7 shipping build:

```
UnrealDuck/Binaries/Win64/UnrealDuckClient-Win64-Shipping.exe   (game module, ~137 MB)
UnrealDuck/Content/Paks/UnrealDuck-WindowsClient.{pak,ucas,utoc} (IoStore, Oodle)
```

A full asset dump finds no flag anywhere in the client: no literal, no encoded form, no texture,
no text asset. The useful finding is in `DefaultGame.ini` inside the pak:

```ini
[/Script/UnrealDuck.DuckGameInstance]
DedicatedServerAddress=109.120.147.90:24115
```

UDP 24115 on that host is live. It silently drops query probes, but it doesn't return ICMP
unreachable the way closed ports do. The only content sink in the client is the RPC
`ClientReceivePayload(MessageTitle, ImageBytes)`, which fills a "Message received" widget. Nothing in
the client calls it locally, so the flag has to come from the server.

`DefaultEngine.ini` also has CoreRedirects that rename the route-record and GameMode properties to
Greek gibberish (`DuckRouteRecord.N4 → ηψχ` and so on). That's obfuscation of the data layout, not a cipher.

## 2. The route

The `AUnrealDuckGameMode` constructor (`0x144387770`) hardcodes the route as doubles:

| field | value |
|---|---|
| volume extents | (1000, 1000, 260) |
| volume 0 / 1 / 2 | (−1900, −1900, 540) · (−1900, +1900, 540) · (+1900, +1900, 540) |
| endpoint | (+1900, −1900, 540) |

`FUN_144389c10` spawns one `ASessionVolume` per point and gives each a letter code equal to its spawn
index (`mov byte ptr [rdi+0x2c0], bpl`): 0, 1, 2.

The volumes start at z = 280. Standing on the ground (capsule centre z≈92) never touches them. You have
to be up on the 200‑high blocks/ledges around the arena edge. A ramp near the SW corner leads onto a
perimeter ledge that runs past all four corners.

## 3. The hidden mechanic: cheat letters

Overlap is detected **client-side** on the local PlayerController:

* **OnEnterVolume** (`FUN_144391670`) stores the active code at `PC+0x7c8`, appends it to the
  visited list at `PC+0x7b8` and resets the per-volume state.
* The **InputKey handler** (`FUN_14438f5f0`, PC vtable slot 441) runs on each letter key press
  while a volume is active and fewer than 5 letters are recorded. It stores `letter − 'A'` into the
  byte array at `PC+0x808` and mixes it into three state words:

```c
v   = ((1 - ch) * 0x1b + (0x2f6cb09a ^ 0xffffffe5)) & 0x3f;   // ch = 'A'..'Z'
v   = ((v >> 3 ^ v) * 0xd + 0x11) & 0x3f;
f6  = ((f6 & 0xffffff) << 6) | v;                             // PC+0x7b0
s804 = rotl((v + 1) * 0x54e31f9b ^ s804, 7) + 0x2c8b91ef;     // PC+0x804
fc  = rotl((s804 ^ f6) + 0x7b642d11, 9) ^ f6 * 0x1f5d3b79;    // PC+0x7e0
```

* **OnLeaveVolume** (`FUN_144391890` → `FUN_14438b8a0`) folds the state with the matching
  `FDuckRouteRecord` (7 × u32) into a hash and sends `ServerPushCheatLetter(code, letters)`:

```c
u9 = ((rotl(fc + r[2], 11) ^ rotl(r[6] + f6, 5)) + (r[4] ^ s804)) ^ r[0];
u4 = f6 + 0x36d5e22b + r[4];
h  = (rotl(u9, 7) + (rotl(r[2], 3) ^ r[6])) ^ rotl(u4, 13);
// correct iff h == r[5]
```

The three records are built in `FUN_144380750` (immediates plus two 16‑byte constants at
`0x14711a990` / `0x14711aaf0`):

```
rec0 = 6f37aa0b 0 112bb232 29b1711a 45d39389 b2dcbf59 6f4b4eda
rec1 = 17d98198 1 42413596 73257244 57d52250 2523ab39 203585fc
rec2 = 2f48611f 2 39c19d54 158b4d73 583a99d9 b01e4f4d 2b74299a
```

That's only 26⁵ ≈ 11.9 M candidates per volume, so I brute-forced it (`brute.c`, 0.2 s):

```
rec0 len5: ILOVE
rec1 len5: DUCKS
rec2 len5: ALOTT
```

There's exactly one hit per record. A random hit has odds of about 11.9M / 2³² ≈ 0.003, so these are clearly the intended codes.

## 4. Running the client on Linux

The previous notes got several things wrong here, so these are the details that mattered:

* **`-nullrhi` isn't stripped.** The string is stored UTF‑16 and an ASCII grep misses it. The client boots
  under Wine 10 with it. With no window, though, there's no input, so the actual run used `-d3d11`
  (Wine's wined3d) inside a private `Xvfb :77`. The UI renders, the 3D view is black, and keystrokes
  can't leak to the real desktop.
* **The connect address is hardcoded.** `FUN_14437fe50` returns the literal `109.120.147.90:24115` and
  ignores `-ServerAddress=`. I patched a copy of the exe (`UDRelay-Win64-Shipping.exe`) to point at
  `127.0.0.1:7777`, where a Python UDP relay (`relay.py`) logged everything. That gave me
  traffic, chat and the kick reasons.
* **`-ConnectOnLaunch` loops.** It re-fires on every BeginPlay, including after joining, so the
  client reconnects over and over. I clicked Play in the menu with xdotool instead.
* **Low resolution.** Software GL is slow. At 1024×640 the client ran at ~1 - 2 FPS and the server
  rubber-banded the duck. At `-ResX=480 -ResY=300` with scalability cvars turned down, it moved at
  normal speed.
* **Idle kick.** The server disconnects you "after 30 seconds without movement" (jumping doesn't count).

### Position feedback

Yama `ptrace_scope=1` only allows a process to read its ancestors' children, so the controller
(`ctl.py`) **spawns the game as its own child** and reads `/proc/<pid>/mem`:

* PlayerController = heap object whose vtable is `0x147118aa0`
* `PC+0x2f8` → Pawn, `Pawn+0x1c0` → RootComponent, `Root+0x1f0` → ComponentToWorld (FTransform with
  padded double vectors: quat | xyz,pad | scale,pad), giving the world position
* The route state can be read the same way (`PC+0x7c8` active code, `PC+0x7b8` visited list,
  `PC+0x808` recorded letters, `PC+0x7e8` per-code hash diffs)

I tried teleporting by writing the location: the server snapped it back, so movement is
server-authoritative and the duck has to actually walk. Movement is relative to the spawn yaw, which
changes between spawns. I read it from the pawn's quaternion and mapped W/A/S/D to world axes.

## 5. The run

Spawn at (0, 0, 302), yaw 0, so W = +x and D = +y.

1. Walk to (−700, −1200) on the ground, then hold `S` (−x) with a few jumps. The duck climbs a ramp
   onto the west ledge at (−1864, −1516, 292). The visited list becomes `[0]`, so the duck is in volume 0.
2. Type `ilove`. The recorded letters read `08 0b 0e 15 04` = I L O V E.
3. Hold **only** `D` (+y) along the ledge to y = 1790. Leaving volume 0 sends the push, and entering
   volume 1 doesn't record anything because no new key press happens inside it. Visited = `[0,1]`.
   Type `ducks`.
4. Hold only `W` (+x) along the north ledge to x = 1818. Visited = `[0,1,2]`. Type `alott`.
5. Hold only `A` (−y) along the east ledge to the endpoint (1613, −1850). All client-side diffs are
   0 and the "route complete" flag at `PC+0x7e4` is 1.

The server broadcasts **"quackrun completed the route and can head to the end."**, and on reaching
the end the client receives `ClientReceivePayload`: a "Message received" widget with a handwritten
image:

```
SOLARCTF{unr34l_3ng1n3_p4th_f1nd1ng_0n_w1nd0ws}      ("all lowercase")
```
