# `blinking.wav` — Stegano w pliku WAV

> **Autor:** Paweł Murdzek
> **Kategoria:** Steganografia / forensics
> **CTF:** ECSC
> **Flaga:** `ECSC{W3lc0m3_1n_K4ir}`

---

## Treść zadania

Otrzymujemy plik `blinking.wav` oraz historyjkę:

> Znajdź ukrytą flagę w pliku WAV. Pamiętaj, traktuj plik muzyczny jako jednowymiarową siatkę. Poniższa historyjka może ci się przydać.
>
> 1. Ustal współrzędne Doliny Królów w Egipcie oraz miasta Luksor.
> 2. Wyznacz różnicę między tymi miejscami.
> 3. Tak długo, jak płynie Nil, tak bardzo dzieli tę zagadkę.
> 4. Początku odkrycia szukaj na podłodze.
> 5. Czasem, aby zrobić kolejny krok, musisz zadzwonić do Sfinksa i zagrać z nim w oczko.

Format flagi: `ECSC{...}`.

---

## Rozpoznanie pliku

```
Format:      WAV / PCM
Sample rate: 44 100 Hz
Bit depth:   16-bit signed (int16)
Kanały:      stereo (L, R)
Próbek:      2 557 062 na kanał (≈ 58 s)
Header:      tylko `fmt ` + `data` (brak ukrytych chunków, brak trailera)
```

Audio jest realnym utworem muzycznym — `corr(L, R) ≈ 0.82`, dominują częstotliwości muzyczne (F4, C5, E5, G5). Klasyczna analiza widmowa nic nie ujawni — i zagadka to wprost mówi: **nie używaj spektrogramu, traktuj plik jako 1D siatkę próbek**.

---

## Mapowanie wskazówek na algorytm

| Wskazówka | Interpretacja |
|---|---|
| **„Jednowymiarowa siatka"** | Czytamy próbki jako płaską tablicę `int16`, bez analizy widma. |
| **„Dolina Królów (zachód) i Luksor (wschód)"** | Geograficznie Dolina Królów leży na zachodnim brzegu Nilu, Luksor na wschodnim. W stereo: **zachód = kanał lewy (L)**, wschód = kanał prawy (R). |
| **„Wyznacz różnicę"** | Skarby chowano w Dolinie Królów — flaga jest zaszyta wyłącznie w **kanale L**, nie w R. To „różnica" tych miejsc. |
| **„Tak długo, jak płynie Nil, tak bardzo dzieli zagadkę"** | Próbki flagi są **rozdzielone** stałym odstępem na tle muzyki. Krok pomiędzy kolejnymi znakami = **10 próbek**. |
| **„Początku odkrycia szukaj na podłodze"** | „Podłoga" / floor / dół — szukamy **najwcześniejszej pozycji** w L, od której zaczyna się ciąg ASCII otwierający się sekwencją `ECSC{`. Ta pozycja to **indeks 20977**. |
| **„Sfinks i oczko (21)"** | Sfinks pilnuje sekretu — większość próbek to zwykła muzyka i trzeba je **odsiać**. Czytamy ze stałym krokiem i przyjmujemy tylko wartości w zakresie ASCII drukowalnym (32–126). |

---

## Kluczowa obserwacja

Każdy znak flagi został zapisany **dosłownie** jako wartość próbki `int16` w kanale lewym, równa kodowi ASCII danego znaku (np. `'E'` → próbka o wartości `69`). Próbki flagi są rozmieszczone **co 10 sampli**, począwszy od pozycji **20977**, na tle realnej muzyki:

```
L[20977] =  69  → 'E'
L[20987] =  67  → 'C'
L[20997] =  83  → 'S'
L[21007] =  67  → 'C'
L[21017] = 123  → '{'
L[21027] =  87  → 'W'
L[21037] =  51  → '3'
L[21047] = 108  → 'l'
L[21057] =  99  → 'c'
L[21067] =  48  → '0'
L[21077] = 109  → 'm'
L[21087] =  51  → '3'
L[21097] =  95  → '_'
L[21107] =  49  → '1'
L[21117] = 110  → 'n'
L[21127] =  95  → '_'
L[21137] =  75  → 'K'
L[21147] =  52  → '4'
L[21157] = 105  → 'i'
L[21167] = 114  → 'r'
L[21177] = 125  → '}'
```

Pozostałe próbki w okolicy mają „normalne" wartości muzyczne (rzędu ±1500), więc próbki flagi wystają jako wyraźne piki w bardzo wąskim zakresie.

> ⚠️ **Pułapka:** „naiwna" filtracja `chr(v) for v in L if 32 <= v <= 126` daje **zanieczyszczony** wynik — `ECSC{hW3lc$0m3_1n_K4ir}` — bo audio przypadkiem trafia w drukowalny ASCII między prawdziwymi znakami flagi (np. `L[21025] = 104 = 'h'`, `L[21058] = 36 = '$'`). Trzeba czytać **dokładnie ze stałym krokiem 10** od pozycji 20977.

---

## Rozwiązanie

```python
import scipy.io.wavfile as wav

rate, data = wav.read("blinking.wav")
L = data[:, 0]                    # kanał lewy = "Dolina Królów" (Zachód)

START, STEP = 20977, 10
flag = []
for i in range(START, len(L), STEP):
    v = int(L[i])
    if not (32 <= v <= 126):
        break
    flag.append(chr(v))
    if v == ord('}'):
        break

print(''.join(flag))   # ECSC{W3lc0m3_1n_K4ir}
```

---

## Flaga

```
ECSC{W3lc0m3_1n_K4ir}
```

**Dekodowanie leetspeak:** `W3lc0m3_1n_K4ir` → **„Welcome in Kair"** (Kair = Cairo po polsku) — nawiązanie do Egiptu z fabuły zagadki.

---

## Wnioski / lessons learned

- Stereo WAV jest naturalnym nośnikiem stego — narracja o „zachodzie i wschodzie Nilu" sprytnie kieruje na rozdzielenie kanałów.
- Najprostsza forma steganografii w PCM: **wstawienie wartości ASCII bezpośrednio jako wartości próbek `int16`** w wybranych pozycjach. Takie próbki są niesłyszalne (krótkie ciche „kliknięcia"), a wyglądają jak wąskie piki w środku normalnego sygnału.
- Pułapka pierwszego podejścia: wzór `floor((L − R) / 6650)` z literalnego odczytu narracji **nie ma matematycznej szansy zwrócić ASCII** — bo `|L − R| ≤ 12805`, więc `/6650 ∈ {−2, −1, 0, 1}`. Liczby z historyjki to klimatyczne mylące tropy; istotne są działania:
  - „kanał L (Dolina Królów)",
  - „filtruj na ASCII (Sfinks pilnuje)",
  - „znajdź początek od `E` (na podłodze)",
  - „idź stałym krokiem (Nil dzieli regularnie)".
- Naiwna filtracja całego kanału po ASCII łapie szum z muzyki — niezbędny jest **stały krok** od konkretnego startu.
- Zawsze warto najpierw sprawdzić **trywialną hipotezę**: „a może flaga jest po prostu zapisana wprost, bez żadnej matematyki?" przed brute-forcem dzielników i offsetów.

---

## Pliki w tym katalogu

| Plik | Opis |
|---|---|
| `blinking.wav` | plik z zagadki (stereo PCM 16-bit, 44.1 kHz) |
| `writeup.md` | ten dokument (do czytania) |
| `writeup.py` | uruchamialny skrypt — wczytuje WAV i wypisuje flagę |
| `test.py` | pierwsza, błędna próba (interpretacja `L − R`/6650) |
