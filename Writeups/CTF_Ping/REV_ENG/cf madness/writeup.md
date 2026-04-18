# cf madness — writeup

**Autor zadania:** lexu
**Format flagi:** `ping{.*}`
**Kategoria:** reverse engineering
**Mój nick:** Paweł Murdzek

---

## Pierwsze spojrzenie

Dostajemy jeden plik: `chall`. Standardowe `file`:

```
chall: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped
```

Stripped, dynamically linked, x86-64. Nic dziwnego na pierwszy rzut oka. Rozmiar ~106KB — jak na prosty flag checker to sporo.

`strings` wyciąga nam:

```
Wrong flag!
Correct flag!
Enter the flag:
%s
```

Klasyczny scenariusz: wpisujesz flagę, dostajesz jedno z dwóch. W porządku.

## Problem — decompilery dostają zawału

Opis zadania mówi wprost: *Ghidra had a stroke, IDA can't decompile, i don't have Binja. Only :SnowmanDecompiler: survived.* Nazwa zadania to "cf madness", czyli control flow madness.

Odpalasz Ghidrę → crash albo bezsensowne bloki. IDA podobnie. Widzę, że to celowe.

Dlaczego? Zaraz się okaże.

## Analiza statyczna — co jest w binarce

### Sekcje

```
.text   addr=0x4003b0  size=89125  (!)
.data   addr=0x419020  size=5184
.bss    addr=0x41a460  size=8600
.rodata addr=0x416240  size=96
```

89KB kodu w `.text` jak na flag checker? Podejrzane.

### Entry point i main

Entry point (`0x4003b0`) to standardowy `__libc_start_main` wrapper. Jako `main` wskazuje `0x4035cc`.

Disassembluję main:

```asm
0x4035cc: push rbp
0x4035cd: mov rbp, rsp
0x4035d0: sub rsp, 0x20
0x4035d4: mov edi, 0x41626e    ; "Enter the flag: "
0x4035de: call printf
0x4035e3: mov esi, 0x41c560    ; bufor na input
0x4035e8: mov edi, 0x41627f    ; "%s"
0x4035f2: call scanf
0x4035f7: mov eax, 0x415f9c
0x4035fc: sub rax, 0x415e31
          ; ... jakieś float operacje ...
0x403614: call strlen
0x403646: call strlen
0x40364b: mov [rip+0x17e33], eax
0x403651: nop
0x403652: nop
...
```

I tu się zaczyna dziw: od `0x403651` do mniej więcej `0x415d00` — **kilkadziesiąt kilobajtów samych nopów**. Coś koło 65KB nopów.

### Prawdziwa logika — `0x415e31`

Gdzieś w okolicach `0x415e31` pojawia się prawdziwy kod. Najważniejszy smaczek — zakończenie tej funkcji:

```asm
0x415f84: cdqe
0x415f86: neg rax
0x415f89: add rax, 0x415f9c
0x415f8f: mov [rbp - 8], rax
0x415f93: mov rax, [rbp - 8]
0x415f97: mov [rsp], rax      ; <-- NADPISUJE ADRES POWROTU NA STOSIE
0x415f9b: ret                 ; <-- SKACZE W LOSOWE (?) MIEJSCE
```

I to jest serce całego obfuscation. Funkcja **sama sobie zmienia adres powrotu** i robi `ret` — co jest klasycznym trikiem control flow obfuscation, który dosłownie wykoleja wszystkie decompilery bazujące na call-graph analysis.

### Trampolina przez NOP sled

Co się dzieje po tym `ret`? Skacze w środek NOP sleda. A NOP slidy mają to do siebie, że CPU po prostu przesuwa się przez nie aż trafi na coś sensownego.

W NOP sledzie co ~1052 bajty są malutkie "wyspy" kodu (72 sztuki) — ale to tylko decoy, liczą jakieś `r11 = 0x16d15` bez żadnego efektu ubocznego. CPU przez nie przelatuje i wraca do `0x415e31`.

Efekt: pętla, w której `0x415e31` jest wywoływana wielokrotnie, za każdym razem przetwarzając jeden znak flagi, a potem via spreparowany `ret` wskakuje z powrotem w NOP sled, który ją ponownie wywołuje.

### Jak działa licznik iteracji?

Adres `ret`-a jest kodowany jako **80-bitowy float x87** na `0x41b490`. Wartość startowa to `726 × (strlen + 1)`. Każda iteracja zmniejsza go o 726. Target address: `0x415f9c - float_value`.

To jest właśnie to co zabija Ghidrę i IDA — operacje na x87 80-bit floatach jako indirect branch target. Żaden popularny decompiler tego nie ogarnia.

Po `strlen + 1` iteracjach float schodzi do zera i następuje call do check function zamiast kolejnej iteracji.

### Funkcja check (`0x403544`)

Ta funkcja:
1. Wywołuje dispatcher (który wcześniej wypełnił `computed_array` pod `0x41a480`)
2. Porównuje `computed_array[i]` z `reference_array[i]` (pod `0x419460` w `.data`)
3. Jeśli wszystko się zgadza — `puts("Correct flag!")`, jeśli nie — `puts("Wrong flag!")`

Ciekawostka: zarówno ścieżka poprawna jak i błędna kończą się `idiv` przez zero. Binarka crashuje po wypisaniu wyniku — kolejny trick na utrudnienie debuggowania.

### Struktura computed_array

Każda iteracja wpisuje **2 wartości** do `computed_array`:

**Wartości parzyste** `[2*i]` — niezależne od flagi:
```
(-559038737 + 726 * (strlen + 1 - i)) & 0xffffffff
```
Zależą wyłącznie od długości flagi. Pozwala to wydedukować długość: 102 niezerowe wpisy w reference array / 2 wpisy na iterację = **51 znaków** flagi.

**Wartości nieparzyste** `[2*i + 1]` — zależne od znaku flagi:
```
((0xdeadbeef XOR flag[i]) XOR (i * 0x1337) XOR (counter * 0xabcd)) & 0xffffffff
```
Gdzie `counter`:
- `i = 0`: counter = 1337 (inicjalna wartość w `.data` pod `0x419040`)
- `i > 0`: counter = i - 1

### Tablica wskaźników funkcji

W `.data` pod `0x419060` jest 127 wskaźników (8 bajtów każdy) do malutkich funkcji w `.text`. Każda z nich przetwarza jeden znak flagi i wpisuje wynik do `computed_array`. To jest dispatcher.

## Odwrócenie

Mając formułę, odwrócenie jest trywialne:

```python
for i in range(51):
    counter = 1337 if i == 0 else (i - 1)
    target = refs[2*i + 1]
    for c in range(256):
        result = ((0xdeadbeef ^ c) ^ (i * 0x1337) ^ (counter * 0xabcd)) & 0xffffffff
        if result == target:
            # znalazłem znak flagi
```

Brute-force po 256 możliwych bajt wartościach — błyskawiczne.

## Flaga

```
ping{n0_c0mp1l3r_w45_hur7_dur1ng_m4k1ng_7h15_ch4ll}
```

## Podsumowanie tricków

| Trick | Efekt |
|-------|-------|
| 65KB NOP sled | Decompilery gubią control flow |
| Computed return via `mov [rsp], rax; ret` | Żaden call-graph analyzer tego nie śledzi |
| 80-bit x87 float jako indirect branch target | Ghidra/IDA nie interpretują x87 jako adresu skoku |
| `idiv` przez zero na końcu | Crash zamiast normalnego wyjścia, utrudnia debugging |
| 127 małych "funkcji-duchów" w NOP sledzie | Decoy dla analizy statycznej |

## Narzędzia użyte

- `capstone` (Python) — disassembly
- `pyelftools` (Python) — analiza sekcji ELF
- Własny skrypt Python do statycznej analizy i brute-force
