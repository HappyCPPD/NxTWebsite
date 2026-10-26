# Welcome

**Event:** HITCON CTF 2026
**Category:** misc
**Flag:** `hitcon{/goal_Solve_ALL_challenges_on_<https://ctf2026.hitcon.org>_!}`

---

## Challenge

Description text (rendered):

> **Welcome** to HITCON CTF 2026 !
>
> ↓↓↓

Followed by a markdown "reference-style link definition" line:

```
[//]: # (hitcon{/goal_Solve_ALL_challenges_on_<https://ctf2026.hitcon.org>_!})
```

![The raw challenge description, with the flag in the hidden comment line](../images/writeups/welcome-description.png "1130x590")

## Solution

`[//]: # (...)` is CommonMark's **link reference definition** syntax. A line of the
form `[label]: destination "title"` is *not rendered* by any compliant markdown
renderer (including GitHub-flavoured markdown), because it is metadata consumed by
the parser.

The challenge author hid the flag inside the *label/comment* position, so it is
invisible in the rendered description but present verbatim in the raw source.

Reading the raw challenge description (or the page source / API response for the
challenge, e.g. `/api/challenges` or the ctfd challenge JSON) reveals:

```
hitcon{/goal_Solve_ALL_challenges_on_<https://ctf2026.hitcon.org>_!}
```

No binaries, no remote service. Zero exploitation required - pure "read the raw
source instead of the rendered page" trick.

## Flag

```
hitcon{/goal_Solve_ALL_challenges_on_<https://ctf2026.hitcon.org>_!}
```

## Takeaway

- Always diff **rendered** content vs **raw** source. HTML comments `<!-- -->`,
  markdown reference definitions `[x]: y`, and `<details>`/alt-text all survive
  into the API payload.
- Cost: ~30 seconds. Points: 50.
