# CTF writeup — flaga w poprzedniej nazwie pliku usuniętego przez SDelete

**Autor:** Paweł Murdzek
**Data:** 2026-05-06
**Obraz dysku:** `win11-ctf.E01` (ten sam obraz Win11 Home, hostname `WIN11-CTF`)

## Treść zadania

> Jeden z użytkowników ukrył flagę jako jedną z poprzednich nazw pewnego pliku, który następnie usunął za pomocą microsoftowego narzędzia do bezpiecznego usuwania „sdelete". Znajdź tę flagę.

## Flaga

```
{t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}
```

Pełna nazwa pliku z flagą: `{t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}.txt`
Plik istniał u użytkownika **Johnny**.

## TL;DR

`SDelete` skutecznie nadpisuje **zawartość** pliku, ale każda zmiana nazwy (w tym wewnętrzne renaming `AAAAAA.AAA → BBBBBB.BBB → … → ZZZZZZ.ZZZ` które robi sam SDelete w trybie `-r` przed usunięciem) jest zapisywana w **NTFS USN Journal** (`$Extend\$UsnJrnl:$J`). USN to dziennik zmian woluminu — rekordy są kolejkowane i zachowywane do momentu wyrotowania. Z journala odtworzyłem cały łańcuch rename'ów dla usuniętego pliku i znalazłem flagę w jednej z jego poprzednich nazw.

## Środowisko

To samo co w `last_preview/writeup.md`:

- Windows 11 Pro, Python 3.11, Git Bash
- `C:\Tools\dfir\venv` z `dissect.target[full]` (Fox-IT)
- używane moduły: `dissect.ntfs.usnjrnl`, `dissect.target` (do mountowania E01 i rezolwowania FRN przez MFT)

## Dlaczego USN Journal

`SDelete` (Mark Russinovich, Sysinternals) gwarantuje że **dane** pliku są nadpisane wzorcami losowymi. Nie gwarantuje natomiast że metadane systemu plików (MFT, USN, log file) zostaną wyczyszczone — i nie może tego zagwarantować, bo NTFS sam zapisuje historię zmian.

W trybie `-r` (rename) `SDelete` przed usunięciem zmienia nazwę pliku 26 razy kolejnymi literami alfabetu — mechanizm zaprojektowany żeby ukryć oryginalną nazwę w katalogu. Ale każdy rename idzie przez Win32 API → NTFS → **USN journal entry z `RENAME_OLD_NAME` i `RENAME_NEW_NAME`**, które zawierają tekst nazwy. Stąd po `sdelete -r` mamy w `$UsnJrnl:$J` dokładny zapis wszystkich pośrednich nazw plus 26 znaków łańcucha SDelete plus na końcu `FILE_DELETE`.

USN journal nie cofa się też przy nadpisaniu zawartości — `DATA_OVERWRITE` to tylko bit w polu `Reason`, nie zmienia historii rename'ów.

## Wyciągnięcie `$UsnJrnl:$J`

Plik `$UsnJrnl` ma dwa alternate data streams: `$Max` (header) i `$J` (sam dziennik). NTFS dopuszcza `:` w nazwie ADS, ale FAT/exFAT/Windows shell nie pozwala na taki znak w pliku docelowym. `target-fs cp` zachłysnął się — utworzył plik o nazwie `$UsnJrnl` (bez `:$J`) o rozmiarze 0 B. Obejście: wypisać strumień przez `cat` na stdout i przekierować:

```bash
target-fs win11-ctf.E01 cat 'c:/$Extend/$UsnJrnl:$J' \
    > C:\Tools\dfir\usnjrnl\UsnJrnl_J.bin
# 889 105 472 B  (~ 850 MB)
```

## Triage 1 — szybkie szukanie po nazwach z `{...}`

Przed pełnym parsowaniem strumienia wykonałem szybki sweep — w USN nazwy plików są w UTF-16LE. Najpierw szukałem znanych prefixów flag (`ECSC{`, `flag{`, `CTF{`, `cyber.mil{`, …) — **0 trafień**. Format flagi w tym zadaniu jest inny niż w poprzednim.

Przeszedłem więc na heurystykę: znajdź wszystkie nazwy plików zawierające jednocześnie `{` i `}`, odrzuć GUID-y `{8-4-4-4-12}`:

```python
# C:\Tools\dfir\find_flag_usn.py - skrót
for rec in UsnJrnl(fh).records():
    if "{" in rec.filename and "}" in rec.filename:
        names.add(rec.filename)
# 308 unikalnych → po odrzuceniu GUID-ów: 3
```

Pozostałe trzy:

```
winrt--{S-1-5-21-2076607854-2545489608-1104808445-1002}-.searchconnector-ms
winrt--{S-1-5-21-2076607854-2545489608-1104808445-1005}-.searchconnector-ms
{t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}.txt
```

Pierwsze dwa to systemowe pliki konfiguracji search connector z SID-ami w nazwie. Trzeci wyróżnia się: nieudokumentowany format, ciąg losowych znaków w `{}`. **Kandydat na flagę.**

## Triage 2 — pełny chain rename'ów

Pobrałem `FileReferenceNumber` (FRN) tego rekordu USN — `0x1bdd4` — i zebrałem wszystkie wpisy USN dla tego FRN posortowane po `Usn`. Otrzymałem pełny event log od utworzenia do usunięcia (skrócony do kluczowych etapów):

```
2026-01-27 07:53:37  FILE_CREATE             'New Text Document.txt'
2026-01-27 07:53:44  RENAME → RENAME         'New Text Document.txt' → 'test.txt'

# pierwszy rename na flagę
2026-01-27 07:54:51  RENAME_OLD/NEW          'test.txt' → '{t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}.txt'

# kamuflaż - ręczne rename'y co ~250 ms
2026-01-27 07:54:51..57:
   {flag}.txt → network → module → analysis → module
            → {t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}.txt    ← flaga jeszcze raz
            → window → packet → thread → keyboard → system → script
            → device → module → system → storage → packet → server
            → control → device → control → security → network → packet

# 9 minut przerwy

# 08:03:13 - SDelete w trybie -r:  26 rename'ów + delete (wszystko w 22 ms)
2026-01-27 08:03:13.014  RENAME 'packet.txt'   → 'AAAAAA.AAA'
2026-01-27 08:03:13.016  RENAME 'AAAAAA.AAA'   → 'BBBBBB.BBB'
2026-01-27 08:03:13.016  RENAME 'BBBBBB.BBB'   → 'CCCCCC.CCC'
...
2026-01-27 08:03:13.032  RENAME 'YYYYYY.YYY'   → 'ZZZZZZ.ZZZ'
2026-01-27 08:03:13.035  FILE_DELETE | CLOSE   'ZZZZZZ.ZZZ'
```

Dwa fingerprinty potwierdzają że to właściwy plik:

1. **SDelete signature** — dokładnie 26 rename'ów `AAAAAA.AAA → BBBBBB.BBB → … → ZZZZZZ.ZZZ` w odstępach 2-3 ms, zakończone `FILE_DELETE`. To deterministyczny pattern Sysinternals SDelete w trybie `-r`.
2. **Kamuflaż** — wszystkie inne ręczne rename'y to angielskie słowa (`network`, `module`, `analysis`, `window`, `packet`, …). Tylko `{t4SQ2^mX7(zV0pL9&kS1#nB5@rG8-f}` jest losowym ciągiem znaków w `{}`. Pojawia się dwa razy w sekwencji — user świadomie wmieszał ją w listę zwykłych słów, prawdopodobnie żeby utrudnić trywialny grep po `{`.

## Atrybucja użytkownika

Z pierwszego wpisu USN dla naszego FRN wyciągnąłem `ParentFileReferenceNumber` = `0x1bdc5`. Otworzyłem MFT przez `dissect.target` i zrezolwowałem ten parent record:

```
full_path: Users\Johnny\AppData\Local\Packages\
           MicrosoftWindows.Client.CBS_cw5n1h2txyewy\
           LocalState\EBWebView\Default\Cache\Cache_Data\f_000010
```

Slot MFT `0x1bdc5` od czasu utworzenia naszego pliku został zwolniony i powtórnie przydzielony innemu plikowi (cache WebView2), ale lokalizacja w drzewie folderów potwierdza atrybucję: **plik z flagą żył pod kontem `Johnny`**.

## Czego się nauczyłem

1. **`sdelete` nadpisuje dane, nie metadane.** Gwarancje SDelete dotyczą zawartości pliku. Wszystkie nazwy które plik nosił w trakcie życia są w USN journal i pozostają tam aż journal się przewinie (domyślnie kilkadziesiąt MB do kilku GB, w naszym wypadku 850 MB).
2. **Tryb `-r` zostawia czytelny fingerprint.** Sekwencja `AAAAAA.AAA → BBBBBB.BBB → … → ZZZZZZ.ZZZ` zakończona `FILE_DELETE` w odstępach 2-3 ms to charakterystyczny sygnał użycia SDelete — można po tym wręcz IOC tworzyć dla detekcji „ktoś używał SDelete".
3. **`$UsnJrnl:$J` to ADS** — `target-fs cp` nie obsłuży `:` w nazwie pliku docelowego, ale `target-fs cat` na stdout działa.
4. **Heurystyka `{` w nazwach** zadziałała tu lepiej niż szukanie konkretnego prefixu flagi, bo w tym CTF flagi nie mają stałego prefixu jak `ECSC{` z poprzedniego zadania — różne formaty na różne zadania.
5. **`FileReferenceNumber` to kotwica per-plik.** USN może wspomnieć tę samą nazwę dla wielu plików (rename'y w różnych wątkach), ale FRN jednoznacznie identyfikuje konkretny rekord MFT — grupowanie eventów po FRN daje czysty timeline jednego pliku.

## Pliki w środowisku roboczym

```
C:\Tools\dfir\
├── usnjrnl\
│   ├── UsnJrnl_J.bin           849 MB - dump $UsnJrnl:$J
│   └── err.txt                 (pusty - cat poszedł czysto)
├── find_flag_usn.py            triage: nazwy z `{...}`, GUID filter
├── parse_usn.py                heavy-rename detector (top 5 FRN)
├── trace_flag.py               full event chain dla danego FRN
└── find_parent.py              rezolwer parent FRN -> ścieżka MFT
```

---

— Paweł Murdzek
