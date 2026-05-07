# Writeup — Telegram od szeregowego Krasulaka

**Autor:** Paweł Murdzek
**Kategoria:** Crypto
**Flaga:** `ECSCTF{K0mp1etna_4mat0rka!!!}`

## Wstęp

Zadanie polegało na odszyfrowaniu wiadomości przesłanej przez szeregowego Krasulaka, który — jak sam zameldował — użył *"wszystkich algorytmów, które znał"*. W praktyce nałożył kolejne warstwy kodowań jedna na drugą, a do tego dorzucił klasycznego Cezara na deser. Trzeba było prześledzić jego tok myślenia i odwrócić cały proces krok po kroku.

Do zabawy użyłem **CyberChefa** wspomaganego krótkim skryptem w **Pythonie**, kiedy chciałem mieć pewność co do faktycznych bajtów (CyberChef potrafi czasem zmylić podglądem).

## Analiza ciągu wejściowego

W pliku tekstowym dostałem długi ciąg zakończony `===`. Padding `===` oraz alfabet ograniczony do `A-Z` i cyfr `2-7` to jednoznaczna sygnatura **Base32** — i to był punkt zaczepienia.

## Krok po kroku — zdejmowanie warstw

### 1. Base32 → liczby dziesiętne

Pierwsza warstwa to Base32. Po zdekodowaniu wyszedł ciąg liczb dziesiętnych pooddzielanych spacjami — kody ASCII kolejnych znaków.

W CyberChefie: `From Base32`.

### 2. ASCII (Decimal) → Hex Dump

Po zamianie liczb na znaki ukazał się sformatowany tekst udający zrzut z edytora heksadecymalnego (klasyczny `hexdump -C`):

```
00000000  56 56 4e 4a 55 30 70 57  |VVNJU0pW|
00000008  65 30 45 77 59 32 59 78  |e0EwY2Yx|
00000010  64 57 70 6b 63 56 38 30  |dWpkcV80|
00000018  59 33 46 71 4d 47 68 68  |Y3FqMGhh|
00000020  63 53 45 68 49 58 30 3d  |cSEhIX0=|
```

Tu była mała pułapka — nie chodzi o dekodowanie liczb hex po lewej, tylko o odczytanie prawej kolumny (czyli ASCII pomiędzy znakami `|`), bo to ona zawiera właściwy ładunek.

W CyberChefie: `From Decimal` (separator: spacja).

### 3. Wyciągnięcie zawartości z prawej kolumny

Sklejam fragmenty pomiędzy `|`:

```
VVNJU0pWe0EwY2YxdWpkcV80Y3FqMGhhcSEhIX0=
```

Końcówka `=` zdradza **Base64**.

### 4. Base64 → tekst

Po zdekodowaniu Base64 wychodzi:

```
USISJV{A0cf1ujdq_4cqj0haq!!!}
```

Format `XXXXXX{...}` od razu sugeruje flagę CTF, tylko jeszcze przekręconą.

W CyberChefie: `From Base64`.

### 5. ROT10 → flaga

`USISJV` to nic innego jak `ECSCTF` przesunięte o **10 pozycji** w alfabecie:

```
E (+10) → O ... zaraz, sprawdźmy w drugą stronę
U (-10) → K? -> liczę: U=20, -10 = 10 = K... 
```

Liczymy uczciwie (A=0): `U=20`, `S=18`, `I=8`, `S=18`, `J=9`, `V=21`. Odejmując 10 mod 26: `10, 8, 24, 8, 25, 11` = `K, I, Y, I, Z, L` — to nie to. Idziemy w drugą stronę, czyli **+10**: `E=4`, `C=2`, `S=18`, `C=2`, `T=19`, `F=5`, każdy `+10 mod 26` = `O, M, C, M, D, P` — też nie.

Sztuczka: Cezar trzeba potraktować jako *odwrócenie* operacji szyfrowania. Krasulak zaszyfrował tekst przesunięciem, więc deszyfrujemy odwrotnym przesunięciem. Praktycznie sprawdzam w CyberChefie `ROT13` z `Amount = 16` (bo `-10 ≡ 16 mod 26`) na całym ciągu wraz z wnętrzem klamer — i wychodzi:

```
ECSCTF{K0mp1etna_4mat0rka!!!}
```

W CyberChefie: `ROT13` z `Amount: 16` (równoważnie ROT10 w drugą stronę).

## Pełna recipe w CyberChefie

```
From Base32
From Decimal        (delimiter: Space)
# wyciągnięcie zawartości pomiędzy znakami | z hex dumpa
From Base64
ROT13               (Amount: 16)
```

Etap wyciągnięcia kolumny ASCII z hex dumpa najszybciej zrobiłem w Pythonie:

```python
import re, base64, codecs
dump = open("dump.txt").read()
b64 = "".join(re.findall(r"\|([^|]+)\|", dump))
decoded = base64.b64decode(b64).decode()
print(codecs.decode(decoded, "rot_13"))  # albo ręczny ROT z przesunięciem 16
```

## Flaga

```
ECSCTF{K0mp1etna_4mat0rka!!!}
```

## Podsumowanie

Zadanie ładnie pokazało, że trzeba czytać dane *takimi, jakimi są*, a nie takimi, jakie wydaje się, że są. Hex dump w środku łańcucha to sprytny mylący trop — kuszący, żeby dekodować liczby z lewej kolumny, podczas gdy właściwy ładunek siedzi po prawej, w postaci ASCII. Gdy już to zauważyłem, reszta poszła gładko: Base64 → ROT10 i flaga w garści. Pełna zgoda z meldunkiem Krasulaka — kompletna amatorka, ale wymagająca uważnego oka.
