# CTF writeup — usunięty obraz Painta (czerwony tekst na czarnym tle)

**Autor:** Paweł Murdzek
**Data:** 2026-05-06
**Obraz dysku:** `win11-ctf.E01` (Win11 Home, ~28 GiB skompresowane, hostname `WIN11-CTF`)

## Treść zadania

> Jeden z administratorów utworzył obraz w narzędziu Paint, który zawierał pewien tekst (czerwony tekst na czarnym tle). Obraz został usunięty, czy potrafisz odczytać tę flagę?
> Wskazówka: NIE próbować szukać/odzyskiwać usuniętego pliku.

## Flaga

```
ECSC{4fA9zK2Lp6M8vR5wQ1tB3jY0gH7sXn}
```

## TL;DR

Mimo że plik PNG/BMP został usunięty, **Eksplorator Windows zdążył wygenerować jego miniaturę** i zapisać ją w `thumbcache_*.db` profilu użytkownika. Thumbcache nie jest czyszczony przy usunięciu pliku źródłowego. Flagę odczytałem z PNG w `thumbcache_256.db` użytkownika `John` (offset `0xD6118`).

## Środowisko

### Sprzęt / OS analizy
- Windows 11 Pro 26200
- PowerShell 7 + Git Bash (MSYS2)
- Python 3.11.9

### Stan początkowy
W `C:\Tools` były wcześniej zainstalowane: ZimmermanTools (.NET 9), Volatility3, Binwalk, ExifTool, John, Hashcat, Ghidra. **Brakowało** narzędzia do otwarcia obrazu E01 i do parsowania Windows thumbcache.

### Dostawiłem (bez admina, wszystko w `C:\Tools\dfir`)

```powershell
# katalog roboczy + venv
mkdir C:\Tools\dfir
python -m venv C:\Tools\dfir\venv

# Fox-IT dissect: czyta E01, parsuje NTFS, parsuje thumbcache - pure Python
C:\Tools\dfir\venv\Scripts\pip.exe install "dissect.target[full]" pillow numpy
```

Próba `pip install pytsk3 libewf-python` nie powiodła się — `pytsk3` nie ma wheela dla Windows i wymaga buildu z TSK. **`dissect.target` od Fox-IT** rozwiązuje wszystko czysto pythonowo: zawiera `dissect.evidence` (E01), `dissect.ntfs` i — kluczowy dla zadania — `dissect.thumbcache`.

Z venv dostałem CLI:
- `target-info`, `target-fs`, `target-shell`, `target-mount`
- `thumbcache-extract`, `thumbcache-extract-indexed`

## Rozpoznanie

```bash
target-info win11-ctf.E01
```

```
Hostname       : WIN11-CTF
Os version     : Windows 11 Home (NT 10.0) 26100.7462
Timezone       : Europe/Warsaw
Volumes        : 5 (główny C: NTFS, 63 GB)
```

Userzy w `c:/Users/`:

```
Jack, Jackson, Jim, Jimson, John, Johnny, Johnson
```

Klasyczne CTF-owe „który z siedmiu Jacków-Johnów to admin?".

## Hipoteza

Skoro plik został usunięty, ale nie mamy go odzyskiwać (wskazówka), trzeba znaleźć **kopię, którą Windows zrobił sam**. Lista miejsc rozważonych:

1. **Thumbcache** — `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`. Eksplorator generuje miniatury przy pierwszym pokazaniu pliku. Thumbcache **przeżywa usunięcie pliku**.
2. **Paint UWP LocalState** — nowy Paint v11 ma autosave w `%LOCALAPPDATA%\Packages\Microsoft.Paint_8wekyb3d8bbwe\LocalState\`.
3. **Windows Recall** — `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\<guid>\` (tylko Copilot+ PC).
4. **Clipboard history**, **JumpLists**, **Recent**.

Sprawdziłem 2-4 — Paint LocalState pusty u wszystkich (admin używał klasycznego `mspaint.exe`, nie UWP), Recall niedostępny (Win11 Home), clipboard history brak. **Pozostał thumbcache.**

## Eksfiltracja thumbcache

Skopiowałem cały folder Explorer dla każdego usera:

```bash
for u in Jack Jackson Jim Jimson John Johnny Johnson; do
  target-fs win11-ctf.E01 cp -o "C:\Tools\dfir\extracted\$u" \
    "c:/Users/$u/AppData/Local/Microsoft/Windows/Explorer/"
done
```

### Pierwszy zwrot akcji

Thumbcache w Win11 dzieli się na rozmiary: 16, 32, 48, 96, 256, 768, 1280, 1920, 2560 + warianty (sr, wide, exif). Większy rozmiar = pełniejsza miniatura. Sprawdzenie rozmiarów plików (24 B = pusty header, ~1 MB = preallocated z danymi):

| user    | _16 | _32 | _48 | _96   | _256 | _1280 |
|---------|-----|-----|-----|-------|------|-------|
| Jack    | 1M  | 1M  | 1M  | —     | 1M   | 24    |
| Jackson | 1M  | 1M  | —   | —     | 1M   | 24    |
| Jim     | 1M  | 1M  | 1M  | —     | 1M   | 24    |
| Jimson  | 1M  | 1M  | 1M  | —     | 1M   | 24    |
| **John**| 1M  | 1M  | 1M  | **3M**| 1M   | **1M**|
| Johnny  | 1M  | 1M  | 1M  | —     | 1M   | 24    |
| Johnson | 1M  | 1M  | —   | —     | 1M   | 24    |

Tylko **John** miał niezerowy `_96.db` (i to 3 MB, większe niż preallocate) oraz niezerowy `_1280.db`. Czyli to John wyświetlał w Eksploratorze duże miniatury obrazów. **Admin = John.**

### Ekstrakcja miniatur

```bash
thumbcache-extract C:\Tools\dfir\extracted\John -o C:\Tools\dfir\thumbs\John
```

Narzędzie wyrzuciło `EOFError` w połowie i pominęło `_96.db` oraz `_1280.db`. Ekstrahowałem je osobno (każdy plik DB w izolowanym folderze):

```bash
mkdir C:\Tools\dfir\single96
cp C:\Tools\dfir\extracted\John\thumbcache_96.db C:\Tools\dfir\single96\
thumbcache-extract C:\Tools\dfir\single96 -o C:\Tools\dfir\thumbs_96_John
# 105 plików BMP (i ukryte JPEG udające .bmp)
```

### Triage po kolorach

Skoro szukamy „czerwony tekst na czarnym tle", napisałem skaner HSV:

```python
# C:\Tools\dfir\find_flag.py - skrót
hsv = img.convert("HSV")
for (r,g,b), (H,S,V) in zip(img.getdata(), hsv.getdata()):
    if V < 60: dark += 1
    elif S > 100 and V > 80 and (H < 12 or H > 243): red += 1
# trafienie: dark > 0.95 AND red > 0.01
```

Trafienie w `thumbs_96_John\f1b15736d5fb9fdc\dc9ffbd53657b1f1_96.bmp`:

```
red=0.0152 dark=0.9763  rozmiar 96x72
```

Po upscale 5×: czarne tło z czerwoną linią tekstu **wysoką dokładnie 4 piksele** — nieczytelne. Potrzebowałem większej miniatury.

## Drugi zwrot akcji — `thumbcache_idx.db`

Hash entry: `f1b15736d5fb9fdc` (nazwa folderu = hash little-endian). W tej samej cache db jest plik `thumbcache_idx.db`, który dla każdego entry pamięta **w jakich rozmiarach został wyrenderowany** i **gdzie leży w odpowiednim `thumbcache_NNN.db`**.

Win11 idx (format 32) ma 14 slotów; zmapowałem je do nazw:

```
[16, 32, 48, 96, 256, 768, 1280, 1920, 2560, sr, wide, exif, wide_alternate, custom_stream]
```

Skrypt `parse_idx.py` przeszedł 239 entry indeksu Johna i dla naszego hasha pokazał:

```
identifier=f1b15736d5fb9fdc
flags=0x1000bf
-> size 96  at offset 0x2296e8
-> size 256 at offset 0xd6118
```

**Ten sam plik istnieje też w `thumbcache_256.db` pod offsetem `0xD6118`.** Tam tekst będzie miał ~10 px wysokości — czytelny.

## Trzeci zwrot akcji — bug w `thumbcache-extract`

Próba osobnego wypakowania `_256` od Johna:

```
OSError: [Errno 22] Invalid argument:
'...\\e84eb8f951bc2409\\::{645FF040-5081-101B-9F08-00AA002F954E}_256.bmp'
```

Indeks zawiera entry dla Recycle Bin (`::{GUID}` to Win32 shell folder). `thumbcache-extract` próbuje stworzyć plik z `::` w nazwie — Windows odrzuca. Ekstrakcja crashuje **przed** dotarciem do naszego entry. Dlatego pełna miniatura nigdy się nie wypakowała.

Obejście: ręcznie wczytać entry pod znanym offsetem za pomocą `dissect.thumbcache`:

```python
# C:\Tools\dfir\extract_one.py
from dissect.thumbcache import ThumbcacheEntry
from dissect.thumbcache.thumbcache_file import ThumbcacheFile

with open(r"C:\Tools\dfir\extracted\John\thumbcache_256.db", "rb") as f:
    tcf = ThumbcacheFile(f)
    f.seek(0xd6118)
    entry = ThumbcacheEntry(f, tcf.version)
    Path("TARGET_256.png").write_bytes(entry.data)
```

Output:

```
identifier: dc9ffbd53657b1f1
hash bytes: f1b15736d5fb9fdc
data length: 5012
head bytes: 89504e470d0a1a0a   <- PNG signature
```

5012 bajtów PNG, 256×191 px. Otwarty:

![flaga](candidates_96/TARGET_256.png)

```
ECSC{4fA9zK2Lp6M8vR5wQ1tB3jY0gH7sXn}
```

## Czego się nauczyłem

1. **Win11 thumbcache to skarbnica.** Eksplorator generuje miniaturę przy pierwszym wyświetleniu i nigdy jej nie czyści przy usunięciu pliku. Dla obrazów ≥256 px miniatura w `_256.db` jest pełnym, czytelnym PNG/JPEG.
2. **Rozmiary thumbcache zdradzają zachowanie usera.** Tylko John miał niepuste `_96.db` i `_1280.db` — bo tylko on wyświetlał w Eksploratorze widoki Medium/Extra Large icons. To zawęziło 7 userów do 1 bez sięgania do rejestru / shellbagów.
3. **`thumbcache_idx.db` to mapa.** Per-entry lista offsetów w każdym `thumbcache_NNN.db` — gdy konkretny rozmiar nie wypakował się przez bug narzędzia, idx + ręczny seek wystarczą.
4. **`dissect.target` (Fox-IT)** to dziś najwygodniejsze pythonowe DFIR toolkit pod Windows — czyta E01 i NTFS bez kompilacji, ma dedykowane parsery (`dissect.thumbcache`, `dissect.regf`, `dissect.eventlog`, `dissect.shellitem`, …). Zastępuje setup z TSK + libewf, który na Windows jest bolesny.

## Pliki w środowisku roboczym

```
C:\Tools\dfir\
├── venv\                       venv z dissect.target + pillow + numpy
├── extracted\<user>\           surowe thumbcache_*.db z 7 userów
├── thumbs\<user>\              wypakowane miniatury (per-user)
├── thumbs_96_John\             osobno _96 (po EOFError z full extract)
├── single256\                  pojedynczy thumbcache_256.db Johna
├── candidates_96\
│   └── TARGET_256.png          *** flaga ***
├── find_flag.py                skaner HSV black+red
├── parse_idx.py                czyta thumbcache_idx.db, mapuje hash -> rozmiar -> offset
└── extract_one.py              ręczna ekstrakcja entry po offsecie
```

---

— Paweł Murdzek
