# CTF writeup — flaga rozproszona w pagefile.sys

**Autor:** Paweł Murdzek
**Data:** 2026-05-06
**Obraz dysku:** `win11-ctf.E01` (ten sam obraz Win11 Home, hostname `WIN11-CTF`)

## Treść zadania

> Flaga znajdowała się w pamięci RAM, ale nie wykonano jej zrzutu. System Windows mógł jednak zapisać fragmenty pamięci w innym miejscu na dysku.

## Flaga

```
ECSC{m1@vG4^pL7$rB0&kS9*nQ2#zD5(xX8-j}
```

## TL;DR

`pagefile.sys` to plik wymiany — Windows wyrzuca tam strony pamięci wirtualnej procesów gdy brakuje RAM. Po reboocie/shutdown dane *czasem* zostają (zależnie od ustawienia `ClearPageFileAtShutdown`). Flaga była celowo zapisana w pamięci jako **łańcuch 4 fragmentów**, każdy z markerem wskazującym hex offset i długość kolejnej części. Wszystkie 4 części wylądowały w `pagefile.sys` i można je było zrekonstruować idąc po offsetach.

## Środowisko

To samo `C:\Tools\dfir\venv` z `dissect.target` co w poprzednich zadaniach. Nowych narzędzi nie potrzebowałem — wystarczył Python z `re` i `pathlib`.

## Co Windows zapisuje na dysk z pamięci

| plik | rozmiar w obrazie | co tu jest |
|------|-------------------|------------|
| `C:\pagefile.sys` | **402 MB** | strony procesów wyrzucone z RAM |
| `C:\swapfile.sys` | 256 MB | swap dla aplikacji UWP/Modern |
| `C:\hiberfil.sys` | brak | hibernacja wyłączona |
| `C:\Windows\Minidump\*.dmp` | 3 × kilka MB | kernel BSOD minidumpy |
| `C:\Windows\MEMORY.DMP` | brak | full memory dump nieskonfigurowany |
| `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\` | kilka raportów | crash dumpy WER (kernel + aplikacje) |
| `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\` | wiele AppCrash_* | tylko `Report.wer` (metadane) |

Brak `hiberfil.sys` zamknął drogę do pełnego dumpu RAM przez konwersję hibernacji. Pozostały `pagefile.sys` i `swapfile.sys`. Crash dumpy w WER były tylko kernel-side i metadane, bez user-process memory.

## Wyciągnięcie

```bash
# pagefile.sys ma sparse extents, target-fs cp odtwarza je przez stream:
target-fs win11-ctf.E01 cat 'c:/pagefile.sys' > C:\Tools\dfir\memory\pagefile.sys
target-fs win11-ctf.E01 cat 'c:/swapfile.sys' > C:\Tools\dfir\memory\swapfile.sys
```

Pliki nie są kompresowane — surowe strony 4 KB z pamięci wirtualnej.

## Skan prefiksów

Pierwszy strzał — szukam typowych formatów flag w obu plikach (ASCII i UTF-16LE):

```python
prefixes = ["ECSC{", "flag{", "FLAG{", "Flag{", "CTF{", "ctf{",
            "cyber.mil{", "cyber{", "FLAGA{", "PWN{", "key{"]
for px in prefixes:
    for enc in ("ascii", "utf-16le"):
        cnt = data.count(px.encode(enc))
```

Jedno czyste trafienie w `pagefile.sys`:

```
@0x0461EDA2 (ASCII): ECSC{m1@v <-PART1 O:021ACB71 Len=12
```

Marker `<-PART1` mówi że to **pierwsza część** flagi, a po nim metadane:
- `O:021ACB71` — offset hex, gdzie w `pagefile.sys` znajduje się PART2
- `Len=12` — długość PART2

W swapfile.sys nic nie znalazłem (UWP swap zawiera głównie aplikacje Modern UI).

## Reconstruction łańcucha

Idąc po offsetach z markerów, znalazłem 4 części — każda zawiera własny marker do następnej. Format markeru zmienia się subtelnie między fragmentami (autor zadania bawił się składnią), ale schemat jest spójny: `<wartość><spacja><offset_hex><L|-><długość>`.

| PART | offset                | wartość        | dł. | marker do następnego        |
|------|-----------------------|----------------|-----|-----------------------------|
| 1    | `0x0461ED9F`          | `m1@v`         | 4   | `<-PART1 O:021ACB71 Len=12` |
| 2    | `0x021ACB71`          | `G4^pL7$rB0&k` | 12  | `1149DB85 L:9`              |
| 3    | `0x1149DB85`          | `S9*nQ2#zD`    | 9   | `0F8C19A8-8id`              |
| 4    | `0x0F8C19A8`          | `5(xX8-j}`     | 8   | (kończy się `}`)            |

Surowe odczyty (z `pagefile.sys` w hex+ASCII):

```
PART1 @0x0461ED9F:
  0461ed9f: 45 43 53 43 7b 6d 31 40 76 20 3c 2d 50 41 52 54 31 20 4f 3a 30 32 31 41 43 42 37 31 4c 65 6e 3d
            E  C  S  C  {  m  1  @  v  sp <  -  P  A  R  T  1  sp O  :  0  2  1  A  C  B  7  1  L  e  n  =

PART2 @0x021ACB71:
  021acb71: 47 34 5e 70 4c 37 24 72 42 30 26 6b 20 31 31 34 39 44 42 38 35 4c 3a 39
            G  4  ^  p  L  7  $  r  B  0  &  k  sp 1  1  4  9  D  B  8  5  L  :  9

PART3 @0x1149DB85:
  1149db85: 53 39 2a 6e 51 32 23 7a 44 20 30 46 38 43 31 39 41 38 2d 38 69 64
            S  9  *  n  Q  2  #  z  D  sp 0  F  8  C  1  9  A  8  -  8  i  d

PART4 @0x0F8C19A8:
  0f8c19a8: 35 28 78 58 38 2d 6a 7d
            5  (  x  X  8  -  j  }
```

Składanie: `ECSC{` + `m1@v` + `G4^pL7$rB0&k` + `S9*nQ2#zD` + `5(xX8-j` + `}`

```
ECSC{m1@vG4^pL7$rB0&kS9*nQ2#zD5(xX8-j}
```

## Czego się nauczyłem

1. **`pagefile.sys` przeżywa shutdown** chyba że ustawione `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown = 1`. W tym obrazie ustawienie nie było aktywne — strony procesów wyrzucone z RAM zostały zachowane bez zmian.
2. **Strony w pagefile są fragmentaryczne i niesekwencyjne.** Mapping wirtualny → fizyczny w pamięci jest losowy, więc dwa kolejne offsety w pamięci procesu trafiają do losowych miejsc w `pagefile.sys`. Ofset 0x021ACB71 i 0x0461ED9F są fizycznie tysiące stron od siebie, mimo że w pamięci procesu mogły być sąsiadami.
3. **Marker-based fragmentacja** — autor zadania nie ufał że fragment z flagą trafi w jedną stronę pagefile, więc rozbił flagę na 4 części i każdą zostawił z hardcoded wskaźnikiem (offset + długość) do następnej. To jest celowy CTF design — w realnym świecie taka informacja nie miałaby tych markerów, więc trzeba by korelować przez carving lub wirtualną rekonstrukcję pamięci procesu.
4. **Skan po prefixie flagi działa świetnie pod warunkiem znajomości formatu.** Tu wiedziałem z poprzedniego zadania (zad. 1, thumbcache) że format to `ECSC{...}`, więc jeden grep wystarczył. Bez tego punkt startowy mógłby zająć dużo dłużej.
5. **Brak hiberfil.sys ≠ brak pamięci na dysku.** Nawet bez hibernacji `pagefile.sys` jest kopalnią danych — rzadko wszystko trafia do swapu, ale wystarczy fragment.

## Pliki w środowisku roboczym

```
C:\Tools\dfir\
├── memory\
│   ├── pagefile.sys    402 MB - dump c:\pagefile.sys
│   └── swapfile.sys    256 MB - dump c:\swapfile.sys (nieprzydatny tu)
├── scan_memory.py      sweep prefiksów flag (ASCII + UTF-16LE)
├── find_parts.py       lokalizacja wszystkich markerów <-PARTn
└── follow_chain.py     walk po offsetach + reconstruction
```

---

— Paweł Murdzek
