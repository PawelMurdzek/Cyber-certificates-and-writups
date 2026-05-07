# Digital Forensics Fundamentals — TryHackMe

**Room:** [Digital Forensics Fundamentals](https://tryhackme.com/room/digitalforensicsfundamentals)
**Author of writeup:** Paweł Murdzek
**Category:** Incident Response & Forensics — Introduction

---

## Scenario

A ransom note (`ransom-letter.pdf`) was left along with an attached image (`letter-image.jpg`).
The task is to use basic digital forensics tooling — `pdfinfo` and `exiftool` — to extract
metadata from both artifacts and pivot from that metadata to actionable investigative leads:
the document author, the location where the photo was taken, and the device used to take it.

Files in this folder:

- `ransom-letter.pdf` — the ransom note
- `ransom-letter.doc` — the original Word version (irrelevant for `pdfinfo`, kept for completeness)
- `letter-image.jpg` — image embedded in / attached to the letter

---

## Tooling

| Tool | Purpose |
| :--- | :--- |
| `pdfinfo` (poppler-utils) | Print PDF document metadata (Title, Author, Creator, timestamps, …) |
| `exiftool` | Read/write EXIF, IPTC, XMP metadata from images and many other formats |

Both tools come pre-installed on the THM AttackBox. Installing locally on Debian/Ubuntu:

```bash
sudo apt install poppler-utils libimage-exiftool-perl
```

---

## Task — Metadata extraction

### Q1. Using `pdfinfo`, find the author of `ransom-letter.pdf`.

```bash
pdfinfo ransom-letter.pdf
```

Output (trimmed):

```
Title:          Pay NOW
Subject:        We Have Gato
Author:         Ann Gree Shepherd
Creator:        Microsoft® Word 2016
Producer:       Microsoft® Word 2016
CreationDate:   Wed Feb 23 09:10:36 2022 GMT
ModDate:        Wed Feb 23 09:10:36 2022 GMT
Pages:          1
PDF version:    1.7
```

> Note: running `pdfinfo` against `ransom-letter.doc` is expected to fail
> (`Syntax Warning: May not be a PDF file`) — `.doc` is an OLE compound file,
> not a PDF. For Office documents you would use `exiftool` or `olemeta` instead.

**Answer:** `Ann Gree Shepherd`

---

### Q2. Using `exiftool`, find the street where the photo was taken.

```bash
exiftool letter-image.jpg
```

Relevant lines from the output:

```
Make                 : Canon
Camera Model Name    : Canon EOS R6
GPS Latitude         : 51 deg 30' 51.90" N
GPS Longitude        : 0 deg  5' 38.73" W
GPS Position         : 51 deg 30' 51.90" N, 0 deg 5' 38.73" W
User Comment         : THM{238956}
Lens Model           : EF50mm f/1.8 STM
```

The interesting field is **GPS Position**: `51°30'51.90"N 0°5'38.73"W`.
Pasting those coordinates into Google Maps / OpenStreetMap drops a pin in the
City of London, on **Milk Street** (just off Cheapside, by Guildhall).

**Answer:** `Milk Street`

---

### Q3. What is the model name of the camera used to take this photo?

Same `exiftool` output — the `Camera Model Name` tag answers this directly:

```
Make                 : Canon
Camera Model Name    : Canon EOS R6
```

**Answer:** `Canon EOS R6`

---

## Bonus observations

A few extra things worth noting from the EXIF dump that go beyond the room's questions
but are useful in real investigations:

- **Hidden flag:** `User Comment : THM{238956}` — operators sometimes hide payload-style
  strings in EXIF comments; always grep these.
- **Editing pipeline:** the `History Software Agent` chain shows the photo went through
  *Lightroom Classic 10.2 (Mac) → Camera Raw 14.0 → Photoshop 22.4 (Windows) → GIMP 2.10 (Linux)*.
  That's a forensically rich provenance trail — the suspect used at least three different machines.
- **Lens fingerprint:** `Lens Serial Number : 000029720b` and `Serial Number : 083021002010`
  identify the specific body and lens — strong physical-evidence anchors if the gear is recovered.
- **Timezones:** `Offset Time Original : +03:00` and a London GPS fix don't agree — the camera
  clock was set to a non-UK timezone at capture time. Common when a traveller doesn't update
  the camera clock; useful corroboration for movement timelines.

---

## Takeaways

- `pdfinfo` is the fastest path to PDF document metadata; for `.doc`/`.docx` reach for
  `exiftool`, `olemeta`, or `oletools` instead.
- `exiftool` returns far more than the obvious EXIF — XMP edit history, GPS, lens serial,
  timezone offsets, and embedded user comments are all valuable pivots.
- Metadata is the cheapest pivot in an investigation: zero-cost, often forgotten by
  the adversary, and frequently enough to break a case open.

See also: [[Volatility_and_Linux_Forensics]] · [[Incident_response]] for the wider DFIR toolchain.

---

*Writeup by Paweł Murdzek*
