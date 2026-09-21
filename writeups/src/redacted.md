# REDACTED

**Event:** TISC 2026
**Category:** forensics
**Flag:** `TISC{BRO!RedactPDFsProperlyLah!!!}`

---

## Overview

Level 1 hands over a five-page PDF, `TISC-26-091-SINGULARITY.pdf`. Several
sections of the document are covered with black rectangles, and the challenge
description hints at redaction being the whole point.

## The bug

The PDF was never actually redacted. A black rectangle was drawn over the
sensitive text, but the underlying text objects were left untouched
underneath it - visually hidden, not removed. Anything that reads the PDF's
text layer directly, instead of rendering it to a bitmap first, sees straight
through the boxes.

## Solution

Extract the text while preserving layout, so the redacted section stays
readable in context:

```bash
pdftotext -layout TISC-26-091-SINGULARITY.pdf extracted.txt
```

A section titled "The Flag" turns up in the extracted text, containing:

```text
VElTQ3tCUk8hUmVkYWN0UERGc1Byb3Blcmx5TGFoISEhfQ==
```

The trailing `==` is the giveaway for Base64. Decoding it:

```bash
printf '%s' 'VElTQ3tCUk8hUmVkYWN0UERGc1Byb3Blcmx5TGFoISEhfQ==' | base64 -d
```

```text
TISC{BRO!RedactPDFsProperlyLah!!!}
```

## Takeaway

Drawing an opaque shape over text does not remove it from a PDF's content
stream. Proper redaction means deleting or sanitising the underlying text
before publishing the document, not just covering it visually.
