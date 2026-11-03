# Overgrowth

**Event:** HICyberCon CTF 2026
**Category:** web
**Flag:** `hiCTF{graphql_al1as_batch1ng_brute_f0rces_the_0tp_598998a3d9}`

---

> `hiCTF{graphql_al1as_batch1ng_brute_f0rces_the_0tp_598998a3d9}`

Overgrowth was a 500-point web challenge sitting at 0 solves. It's a tiny "gardening supply" GraphQL API, and the whole thing hinges on one idea the flag basically spells out for you once you've got it. Here's how I got there, including the two or three times I talked myself into the wrong answer first.

## The app

The front page is a static shop. The only interesting surface is `/graphql`, served by Ariadne (Python) on gunicorn behind nginx. Introspection is disabled, so you can't just dump the schema.

You can still recover the schema from error messages. GraphQL tells you when a field doesn't exist (`Cannot query field 'x'`), often with a `Did you mean 'y'?`, and it tells you the types and required arguments when you call something wrong. Field-guessing against that oracle gave me the complete schema:

```
Query:    flag            # gated: "authentication required: log in first"
          me: User
          user(username: String!): User     # unauthenticated — this is the IDOR
          products: [Product!]!
Mutation: login(username, password): AuthPayload
          requestPasswordReset(username: String!): Boolean!
          resetPassword(username: String!, token: String!, newPassword: String!): Boolean!
User:     id, username, email, role, apiKey
```

## The IDOR and the decoy

`user(username:)` isn't auth-gated, so you can read any account unauthenticated:

```graphql
{ user(username:"admin"){ id email role apiKey } }
```

Three users exist: `admin` (role admin), `gardener`, and `sprout`. Admin's `apiKey` comes back as:

```
hiCTF{n0t_the_flag_keep_diggin_this_is_just_an_apikey}
```

That's a decoy, and it's a good one. It's shaped exactly like the real flag and it burns a lot of time. A previous attempt at this challenge got stuck right here, treating the apiKey as the prize and then trying to make it authenticate as a header, a password, a bearer token, everything. It doesn't do any of that. The taunt is the hint - you have to actually *become* admin and read the `flag` field, which only the "head gardener" (admin) is allowed to select.

## Getting in

`login` needs a password I don't have, and it isn't SQL-injectable. The two reset mutations are the way in, and the earlier attempt never found them. The flow is the obvious one:

```graphql
mutation { requestPasswordReset(username:"admin") }          # arms a token, always returns true
mutation { resetPassword(username:"admin", token:"????", newPassword:"...") }   # true when the token is right
```

`requestPasswordReset` leaks nothing - no token in the body, no header, no cookie, and it returns `true` even for users that don't exist, so you can't enumerate with it either. The token is generated server-side and you have to guess it.

I spent far too long assuming the token was a long value I'd have to *predict* - time-seeded RNG, hashes of the username plus a timestamp, fixed seeds, the apiKey run through every transform I could think of. Thousands of candidates, nothing landed.

## The rate limit, and why my brute "failed"

Eventually I noticed something I should have checked on request one. `resetPassword` is rate limited:

```
"rate limit: too many password reset attempts; slow down"
```

About 15 attempts per ~60 seconds, and it's global (per-IP, shared across usernames - resetting `sprout` counts against `gardener`). `requestPasswordReset` is *not* limited.

This quietly explained everything. My big candidate sweeps weren't failing because the guesses were wrong - a rate-limited response has no `data` field, so my code had been scoring every throttled attempt as a miss. Only the first ~15 of each run ever actually hit the resolver. Most of what I thought I'd ruled out had never been tested.

It also reframed the challenge. You don't put a rate limit on a 128-bit random token. You rate-limit something **short and guessable**. The token is meant to be brute-forced; the limit is the thing standing in the way.

## The actual trick - alias batching

The rate limiter counts HTTP requests, not resolver calls. GraphQL lets you alias the same field many times in one operation, and every alias runs:

```graphql
mutation {
  a0: resetPassword(username:"admin", token:"0000", newPassword:"x")
  a1: resetPassword(username:"admin", token:"0001", newPassword:"x")
  a2: resetPassword(username:"admin", token:"0002", newPassword:"x")
  ...
}
```

One request, thousands of guesses, one tick on the rate limiter. I confirmed it by firing 75 resets across three batched requests with no throttling at all, then pushed the batch size up. Ten thousand aliases came back in about six seconds, and with a few worker threads I was doing roughly 5,000 reset attempts per second. A full numeric space is minutes, not months.

## Bruting the OTP

My first guess was a 6-digit OTP (`000000` - `999999`). Clean miss across the whole million - which was useful, because it ruled out `randint(100000,999999)` and friends. Then I remembered the apiKey format, `ak_user_gardener_0001`, with its 4-digit zero-padded suffix, and tried a **4-digit** space.

It hit immediately. Admin's reset token on that instance was `6036`, and `resetPassword` returned `true`, setting the password to one I chose.

## The last gate

Logging in returns a token:

```json
{"login":{"token":"75yHePX3jTTZagT-KBas7GcCFtP8gmWK","user":{"id":"1","role":"admin"}}}
```

No `Set-Cookie`. That detail matters, and it's why my earlier attempts to forge a session went nowhere - there's no cookie to forge, and the token isn't a JWT. Auth is just the raw token echoed back in the `Authorization` header:

```
Authorization: 75yHePX3jTTZagT-KBas7GcCFtP8gmWK
```

With that header on, `{ flag }` stops saying "log in first" and hands over:

```
hiCTF{graphql_al1as_batch1ng_brute_f0rces_the_0tp_598998a3d9}
```

## What tripped people up

- The decoy apiKey is designed to eat your time, and it works. Finding admin's key is not the goal; authenticating as admin is.
- Introspection being off makes the reset mutations easy to miss. You have to go find them by name.
- The rate limit silently poisons naive brute scripts - throttled replies look like clean misses unless you check for the error.
- It's tempting to treat "predictable token" as "I must reverse the generation algorithm." Here the move was simpler: notice the limiter is per-request, batch past it, and brute a tiny 4-digit space.

## Reproducing it

`brute.py` in this folder does the whole chain against a fresh instance - enumerate, arm the reset, batch-brute the 4-digit space, reset admin, log in, and print the flag:

```
python3 brute.py https://overgrowth-<id>.chall.hiddeninvestigations.net admin 4d
```

The reset token is regenerated per instance, so the specific value (`6036` here) changes every time; the 4-digit space doesn't.
