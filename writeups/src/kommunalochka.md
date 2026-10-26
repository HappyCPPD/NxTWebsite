# Kommunalochka

**Event:** SolarCTF
**Category:** web
**Flag:** `SOLARCTF{W1ldc4rd_DN3_R00m}`

---

## Challenge

The site is a communal apartment (a kommunalka). You can try to enter other
people's password-protected rooms or register a room of your own.

## Solution

I registered my own room under a username nobody else had taken and set a
password.

Once I had a room, the URL showed how rooms are addressed:

```
<username>.<ip>.nip.io:<port>
```

Each room is a subdomain on a wildcard DNS service, and the username in the
host is what decides whose room you get. The apartment's building manager in a
kommunalka is the upravdom, so that was the room worth getting into.

In Burp, I reloaded my room page and changed the username in the request to
`upravdom`. The server served the manager's room, with the flag:

```
SOLARCTF{W1ldc4rd_DN3_R00m}
```

## Takeaways

- When identity lives in the hostname, editing the host header or subdomain in
  a proxy is often all it takes.
- Wildcard DNS services like nip.io make every subdomain resolve, so the server
  has to check who you are on its own.
