"""
Writeup: blinking.wav (ECSC CTF — stegano w pliku WAV)
Autor: Pawel Murdzek

Flaga: ECSC{W3lc0m3_1n_K4ir}

==============================================================================
ZAGADKA
==============================================================================
"Znajdz ukryta flage w pliku WAV. Pamietaj, traktuj plik muzyczny jako
 jednowymiarowa siatke. Ponizsza historyjka moze ci sie przydac.

  Ustal wspolrzedne Doliny Krolow w Egipcie oraz miasta Luksor.
  Wyznacz roznice miedzy tymi miejscami.
  Tak dlugo, jak plynie Nil, tak bardzo dzieli te zagadke.
  Poczatku odkrycia szukaj na podlodze.
  Czasem, aby zrobic kolejny krok, musisz zadzwonic do Sfinksa
  i zagrac z nim w oczko."

Format flagi: ECSC{...}

==============================================================================
INTERPRETACJA WSKAZOWEK
==============================================================================
1) "Traktuj plik jako jednowymiarowa siatke"
   Plik WAV (PCM 16-bit, stereo, 44.1 kHz) traktujemy jako sekwencje sampli
   - liczb int16. Po wczytaniu przez scipy mamy macierz (N, 2):
   kolumna 0 = kanal lewy (L), kolumna 1 = kanal prawy (R).

2) "Wspolrzedne Doliny Krolow oraz miasta Luksor"
   - Dolina Krolow lezy na ZACHODNIM brzegu Nilu (miejsce ukrycia skarbow).
   - Luksor lezy na WSCHODNIM brzegu.
   W stereo: zachod = kanal LEWY, wschod = kanal PRAWY.
   Skarb (= flaga) jest schowany w kanale LEWYM.

3) "Wyznacz roznice miedzy tymi miejscami"
   Pierwszy trop to L - R, ale wlasciwy odczyt: pracujemy z kanalem L
   (Dolina Krolow). Roznica gospodarcza tych miejsc to fakt, ze flaga
   chowa sie tylko w jednym z kanalow - tym zachodnim.

4) "Tak dlugo, jak plynie Nil, tak bardzo dzieli te zagadke"
   Nil dzieli plik regularnym odstepem - sample flagi sa rozmieszczone
   co staly krok (krok = 10 sampli) wsrod muzycznego tla.

5) "Poczatku odkrycia szukaj na podlodze"
   "Podloga" / floor / dol = pierwsza pozycja, od ktorej zaczyna sie ciag
   ASCII otwierajacy sie sekwencja 'ECSC{'. Ta pozycja to indeks 20977.

6) "Czasem aby zrobic kolejny krok musisz zadzwonic do Sfinksa
    i zagrac w oczko"
   Sfinks pilnuje sekretu. Wiekszosc sampli to muzyka - sample flagi to
   wyjatki o wartosciach trafiajacych w drukowalny ASCII (32-126).
   Trzeba je odsiac stalym krokiem co 10 (ten krok pozostaje stala
   "21-podobna" stawka Sfinksa - poetycka aluzja).

==============================================================================
ALGORYTM
==============================================================================
Kazdy znak flagi zostal zapisany wprost jako wartosc samplu int16
w kanale lewym, rowna kodowi ASCII danego znaku (np. 'E' -> 69).
Sample flagi sa rozmieszczone:
  - poczatek: indeks 20977
  - krok:     10 sampli
  - 23 znaki: 'E','C','S','C','{', ..., '}'

UWAGA: Naiwne "filtruj wszystkie sample L w zakresie 32-126" nie wystarczy
- audio losowo trafia w ten zakres (np. wartosc 104='h' i 36='$' wpadaja
miedzy znaki flagi przez przypadek). Trzeba czytac dokladnie L[20977::10].
"""

import scipy.io.wavfile as wav
import sys

# -----------------------------------------------------------------------------
# Krok 1: Wczytanie pliku
# -----------------------------------------------------------------------------
rate, data = wav.read("blinking.wav")
print(f"[+] WAV wczytany: rate={rate} Hz, ksztalt={data.shape}, dtype={data.dtype}")
print(f"    Czas trwania: {len(data)/rate:.2f} s")

# Kanal LEWY (West / Dolina Krolow - tam, gdzie skarb)
L = data[:, 0]
print(f"[+] Kanal L: {len(L)} sampli, zakres [{L.min()}, {L.max()}]")

# -----------------------------------------------------------------------------
# Krok 2: Odczyt flagi z kanalu L pod stalym krokiem
# -----------------------------------------------------------------------------
START = 20977   # poczatek osadzonego ciagu (na "podlodze" - pierwsza pozycja)
STEP  = 10      # krok miedzy kolejnymi znakami flagi w kanale L

print(f"\n[+] Odczyt L[{START}::{STEP}] z filtrem ASCII drukowalnym (32-126):")

flag_chars = []
for i in range(START, len(L), STEP):
    v = int(L[i])
    if 32 <= v <= 126:
        flag_chars.append(chr(v))
        if v == ord('}'):
            break
    else:
        # Pierwszy sampel poza ASCII = koniec ciagu
        break

flag = ''.join(flag_chars)
print(f"\n[+] FLAGA: {flag}")

# -----------------------------------------------------------------------------
# Sanity check: pokazujemy wartosci sampli flagi
# -----------------------------------------------------------------------------
print(f"\n[i] Wartosci sampli na pozycjach flagi:")
for j, ch in enumerate(flag):
    pos = START + j * STEP
    print(f"    L[{pos}] = {int(L[pos]):4d}  ->  '{ch}'")

# -----------------------------------------------------------------------------
# Dekodowanie zawartosci flagi (leetspeak)
# -----------------------------------------------------------------------------
# ECSC{W3lc0m3_1n_K4ir}
#       W e l c o m e _ i n _ K a i r
#       3 = e, 0 = o, 1 = i, 4 = a
# "Welcome in Kair" - powitanie w Kairze (stolicy Egiptu, niedaleko
# Doliny Krolow i Luksoru wymienionych w zagadce).
print(f"\n[i] Dekodowanie leetspeak:")
print(f"    {flag}  ->  Welcome in Kair (Kair = Cairo po polsku)")
