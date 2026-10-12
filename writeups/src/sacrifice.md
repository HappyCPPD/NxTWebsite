# Sacrifice

**Event:** ByteMe CTF 26
**Category:** forensics
**Flag:** `OWASP{4_50u1_f0r_4_50u1_v0rm1r}`

---

The only artifact is a PCAP. The Vormir theme and the flag format point at a layered extraction challenge, and the order in which the layers come apart is the whole puzzle.

## 1. Triage the capture

Opening the PCAP in Wireshark, the first thing that stands out is a run of ICMP requests. Scrolling further down there is FTP traffic, so following the TCP stream is the natural next move. Several files move between `127.0.0.1` and `127.0.0.1`: manifest files, fuel requests and sensor dump files.

Wireshark's **Download FTP data** option on those streams saves each transferred file out as raw bytes. Everything the FTP session carried was recovered this way.

## 2. The JPEG

Among the exported files is a JPEG. Running `exiftool` on it shows a **password hidden in the comment field**:

```bash
exiftool image.jpg
```

Checking the same file with `binwalk` shows an embedded ZIP archive after the image data:

```bash
binwalk image.jpg
```

## 3. The dead end

At first the embedded archive was ignored. The sensor dump files are numbered `.bin` parts, so the assumption was that they had to be concatenated into one unified file and then unzipped. That did not produce anything usable.

The `.bin` files are decoys. The archive inside the JPEG is the real path, and the password from the comment is what opens it.

## 4. Peeling the layers

Carving the ZIP out of the JPEG (`binwalk -e`, or cut from the offset binwalk reports) and extracting it with the password from the image comment yields a single file, `comms.bin`. Each layer is identified with `file` and unwrapped in turn:

```bash
unzip -P '<password from the JPEG comment>' embedded.zip
file comms.bin        # gzip compressed data
gunzip -c comms.bin > layer1
file layer1           # bzip2 compressed data
bunzip2 -c layer1 > layer2
file layer2           # gzip compressed data
gunzip -c layer2 > layer3
file layer3           # POSIX tar archive
tar xf layer3
```

The layer order is gzip, then bzip2, then gzip, then tar. Trusting `file` at each step matters, because the extension never changes.

## 5. Finding the flag

The tar extracts to a `comms` folder with one subfolder per Avenger, each holding a small `comm.log`: Natasha Romanoff, Bruce Banner, Tony Stark, Nebula, Rhodey, Clint Barton, Steve Rogers and Scott Lang. A README hints at "a soul for a soul" and tells you to find the one who did not come back.

That points straight at Natasha, who is the one who went over the edge on Vormir. Her log is the outlier in two ways:

- It is misnamed `comn.log` instead of `comm.log`.
- It is roughly ten times larger than every other log.

Buried in the middle of the Vormir dialogue is a long base64 string. Decoding it gives the flag directly:

```bash
echo '<base64 string from comn.log>' | base64 -d
```

```text
OWASP{4_50u1_f0r_4_50u1_v0rm1r}
```

## Takeaways

- A PCAP full of FTP is a file-carving problem. Download every stream first and triage each file on its own.
- Metadata and embedded archives beat guessing at how loose parts fit together. Run `exiftool` and `binwalk` on every image before building theories about the other files.
- When an outlier exists (a misnamed file, a file ten times the size of its siblings), it is almost always the intended target.
