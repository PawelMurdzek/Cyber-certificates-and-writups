# Writeup: CrackMe — SERIAL dla LABORATORIUM

**Autor:** Paweł Murdzek
**Kategoria:** Binary Reverse
**Platforma:** cyber.mil
**Plik:** `CrackMe.exe`
**Flaga:** `ECSCTF{90817263}`

## Treść zadania

> Przejęto ważny program do specjalnych zastosowań, który do uruchomienia wymaga
> podania tekstowej nazwy i kodu numerycznego SERIAL. Stosując inżynierię wsteczną
> ustal SERIAL dla nazwy `LABORATORIUM`.
>
> Format flagi: `ECSCTF{SERIAL}`

---

## 1. Rozpoznanie pliku

Pierwszy krok przy każdym binarnym reverse'ie — ustalić, co tak naprawdę dostaliśmy.

```bash
file CrackMe.exe
# CrackMe.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64 Mono/.Net assembly, 2 sections
```

Kluczowa informacja: **Mono/.NET assembly**. To zmienia całą strategię — zamiast
disassemblować natywny kod x86-64, będziemy pracować na poziomie IL (CIL),
który jest dużo czytelniejszy.

## 2. Narzędzia

Do tego zadania wystarczy:

| Narzędzie | Po co |
|---|---|
| `python` + `dnfile` | parsowanie metadanych .NET i wyciągnięcie IL |
| `csc.exe` (.NET Framework) | weryfikacja rozwiązania przez refleksję |
| (alternatywnie) `dnSpy` / `ILSpy` / `dotPeek` | GUI-owy decompiler — szybsza analiza |

W tym writeupie użyłem ścieżki "skryptowej", bo nie miałem zainstalowanego
żadnego dekompilatora GUI. Gdyby był dostępny **dnSpy**, wystarczyłoby otworzyć
w nim `CrackMe.exe` i od razu zobaczyć kod C# klasy `CrackMe.Form1`.

```bash
python -m pip install dnfile
```

## 3. Wstępny rekonesans — strings

Zanim zaczniemy parsować IL, prosty trick — wyciągnijmy stringi (zarówno ASCII
jak i UTF-16, bo .NET używa UTF-16 dla literałów stringowych):

```python
import re
with open('CrackMe.exe', 'rb') as f:
    data = f.read()
print(re.findall(rb'(?:[\x20-\x7e]\x00){4,}', data))
```

Z wyniku najważniejsze:

- `LABORATORIUM` — oczekiwana nazwa
- `PODAŁEŚ PRAWIDŁOWY KLUCZ` / `GRATULACJE` — komunikat sukcesu
- `Podano nieprawidłowy klucz` — komunikat błędu
- `SERIAL powinien składać się z cyfr 0-9 i mieć długość 8`
- `^[0-9]+$` — regex sprawdzający format
- Nazwy metod: `ComputeName`, `ComputeSerial`, `ShiftSerial`, `ComputeSerialNumberSum`

Już teraz wiemy, że SERIAL to **8 cyfr** i mamy 4 funkcje do zrozumienia.

## 4. Wyciągnięcie tabel metadanych .NET

`dnfile` parsuje strumień `#~` z PE i daje dostęp do tabel metadanych. Z tego
wyciągamy listę metod, ich RVA oraz słownik referencji do innych typów/metod.

```python
import dnfile
pe = dnfile.dnPE('CrackMe.exe')
pe.parse_data_directories()
mdt = pe.net.mdtables

for i, m in enumerate(mdt.MethodDef.rows):
    print(f"0x06{i+1:06x} RVA=0x{m.Rva:x} {m.Name}")
```

Interesujące metody:

```
0x06000006 button1_Click           (główna walidacja)
0x06000007 ComputeSerialNumberSum
0x06000008 ComputeSerial
0x06000009 ShiftSerial
0x0600000a ComputeName
```

## 5. Disassembler IL

Napisałem prosty disassembler IL (plik `disasm.py`) — czyta nagłówek metody
(tiny/fat header), iteruje opkody i rezolwuje tokeny `0x70xxxxxx` (UserString),
`0x0Axxxxxx` (MemberRef), `0x06xxxxxx` (MethodDef), itd.

Najważniejsze opkody które trzeba znać:

- `02..05` — `ldarg.0..3` (wczytaj argument)
- `06..09` — `ldloc.0..3` (wczytaj zmienną lokalną)
- `0a..0d` — `stloc.0..3` (zapisz do zmiennej lokalnej)
- `28 <token4>` — `call`
- `6f <token4>` — `callvirt`
- `72 <token4>` — `ldstr`
- `61` — `xor`, `5b` — `div`, `58` — `add`, `63` — `shr`
- `33 <off1>` — `bne.un.s` (skok jeśli nierówne)

## 6. Analiza `button1_Click` — szkielet walidacji

```
ldfld textBox1 ; callvirt get_Text   → text1
ldfld textBox2 ; callvirt get_Text   → text2

if (text1 != "LABORATORIUM") goto error_name

nameVal = ComputeName(text1)         // = 933

if (text2.Length != 8) goto error_format

shifted = ShiftSerial(text2)
ComputeSerialNumberSum(shifted)      // wynik wyrzucony — pewnie pozostałość
serial2 = ComputeSerial(shifted)

if (ComputeSerialNumberSum(text2) != 36) goto error_invalid
if (int.Parse(shifted) / 1867 != 53480) goto error_invalid
if (nameVal != serial2) goto error_invalid

MessageBox.Show("PODAŁEŚ PRAWIDŁOWY KLUCZ", "GRATULACJE")
```

Czyli mamy **trzy** prawdziwe ograniczenia:

1. `sum_cyfr(text2) == 36`
2. `int(shifted) / 1867 == 53480` (dzielenie całkowite!)
3. `ComputeName("LABORATORIUM") == ComputeSerial(shifted)`

## 7. Analiza pomocniczych funkcji

### 7.1 `ComputeSerialNumberSum(s)`

```
suma = 0
for i in 0..s.Length:
    suma += int.Parse(s[i].ToString())
return suma
```

To zwykła suma cyfr stringa.

### 7.2 `ComputeName(name)` — XOR + sum

```
sum = 0
bytes = ASCII.GetBytes(name)        // np. dla "LABORATORIUM"
xored = byte[bytes.Length]
for i in 0..bytes.Length:
    xored[i] = (byte)(bytes[i] ^ 10)   // ldc.i4.s 0x0a
for j in 0..xored.Length:
    sum += xored[j]
return sum
```

Czyli każdy znak XOR-ujemy z `10`, sumujemy. Dla `LABORATORIUM`:

| znak | ASCII | ^10 |
|---|---|---|
| L | 0x4C | 0x46 = 70 |
| A | 0x41 | 0x4B = 75 |
| B | 0x42 | 0x48 = 72 |
| O | 0x4F | 0x45 = 69 |
| R | 0x52 | 0x58 = 88 |
| A | 0x41 | 75 |
| T | 0x54 | 0x5E = 94 |
| O | 0x4F | 69 |
| R | 0x52 | 88 |
| I | 0x49 | 0x43 = 67 |
| U | 0x55 | 0x5F = 95 |
| M | 0x4D | 0x47 = 71 |

`70+75+72+69+88+75+94+69+88+67+95+71 = 933`

### 7.3 `ComputeSerial(shifted)`

```
return 905 ^ ComputeSerialNumberSum(shifted)
```

Stała `0x389 = 905`. Z trzeciego ograniczenia:

```
933 = 905 ^ sum_cyfr(shifted)
sum_cyfr(shifted) = 905 ^ 933 = 44
```

### 7.4 `ShiftSerial(s)` — najciekawsza

Buduje 8-elementową tablicę stringów i konkatenuje je. Konkretnie:

```
shifted[0] = s[0]
shifted[1] = (digit(s[0]) >> digit(s[1])).ToString()
shifted[2] = s[2]
shifted[3] = (digit(s[2]) >> digit(s[3])).ToString()
shifted[4] = s[4]
shifted[5] = (digit(s[4]) >> digit(s[5])).ToString()
shifted[6] = s[6]
shifted[7] = (digit(s[6]) >> digit(s[7])).ToString()
```

Bity parzyste = oryginalne cyfry, bity nieparzyste = poprzednia cyfra przesunięta
w prawo o następną. Bo cyfry są 0–9, a `9 >> 1 = 4`, `9 >> 9 = 0` — wynik zawsze
mieści się w jednej cyfrze, więc długość pozostaje 8.

## 8. Rozwiązywanie układu

Mamy `text2 = d0 d1 d2 d3 d4 d5 d6 d7`. Ograniczenia:

1. `d0+d1+d2+d3+d4+d5+d6+d7 = 36`
2. `int(shifted) / 1867 = 53480`, czyli `shifted ∈ [99847160; 99849026]`
3. `sum_cyfr(shifted) = 44`, czyli `d0 + (d0>>d1) + d2 + (d2>>d3) + d4 + (d4>>d5) + d6 + (d6>>d7) = 44`

Z ograniczenia 2 wiemy że shifted jest postaci `9984????`:

- `shifted[0] = d0 = 9`
- `shifted[1] = d0>>d1 = 9>>d1 = 9` ⇒ `d1 = 0`
- `shifted[2] = d2 = 8`
- `shifted[3] = d2>>d3 = 8>>d3 = 4` ⇒ `d3 = 1`

Zostają 4 cyfry: `d4 d5 d6 d7` z sumą `36 - 18 = 18`.

Najprostszy "ładny" wybór: `shifted == 53480 × 1867 == 99847160` (środek dzielenia
całkowitego — jedyna wartość, dla której równanie spełnione jest "punktowo").

To wymusza `d4=7`, `d4>>d5=1`, `d6=6`, `d6>>d7=0`:

- `7 >> d5 = 1` ⇒ `d5 = 2`
- `6 >> d7 = 0` ⇒ `d7 ≥ 3`

Sprawdzenie sumy: `7 + 2 + 6 + d7 = 18` ⇒ `d7 = 3` ✓ (spełnia też `≥ 3`).

**SERIAL = `90817263`**

## 9. Brute-force (dla pewności)

Żeby się upewnić, napisałem szybkiego brute-force'a (`solve.py`) iterującego po
wszystkich 8-cyfrowych liczbach:

```python
def is_valid(t):
    if len(t) != 8 or not t.isdigit(): return False
    if sum(map(int, t)) != 36: return False
    d = list(map(int, t))
    sh = f"{d[0]}{d[0]>>d[1]}{d[2]}{d[2]>>d[3]}{d[4]}{d[4]>>d[5]}{d[6]}{d[6]>>d[7]}"
    if int(sh) // 1867 != 53480: return False
    if 905 ^ sum(map(int, sh)) != 933: return False
    return True
```

Wynik:

```
90817146 -> 99847340
90817263 -> 99847160   ← dokładnie 53480*1867
90818127 -> 99848420
90818244 -> 99848240
90818541 -> 99848042
90818730 -> 99848033
```

Walidacja w binarnym przyjmuje **dowolny** z tych sześciu (luka w designie —
autor użył `/` zamiast `==`), ale "kanoniczny" — i zwykle wymagany przez
platformę CTF — jest ten z dokładnym dzieleniem: `90817263`.

## 10. Weryfikacja na oryginalnym binarnym

Żeby mieć 100% pewność, że moja interpretacja IL jest poprawna, skompilowałem
mały tester w C# (`Tester.cs`), który przez refleksję wywołuje prywatne metody
`Form1` z `CrackMe.exe` i sprawdza każdy kandydat:

```csharp
var asm = Assembly.LoadFrom(@"CrackMe.exe");
var formType = asm.GetType("CrackMe.Form1");
var inst = Activator.CreateInstance(formType);
var miCN = formType.GetMethod("ComputeName",
    BindingFlags.Instance | BindingFlags.NonPublic);
// ... analogicznie ShiftSerial, ComputeSerial, ComputeSerialNumberSum

int nameVal = (int)miCN.Invoke(inst, new object[] { "LABORATORIUM" });
// ...
```

Kompilacja:

```powershell
& 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /out:Tester.exe Tester.cs
```

> **Uwaga:** jeśli plik został pobrany z internetu, NTFS ma na nim flagę "Zone.Identifier"
> i .NET nie pozwoli załadować go przez refleksję. Trzeba `Unblock-File CrackMe.exe`.

Wynik tester'a potwierdza: wszystkie 6 kandydatów daje `MATCH=True`.

## 11. Flaga

```
ECSCTF{90817263}
```

---

## Kluczowe "lessons learned"

1. **Najpierw `file`** — wykrycie .NET assembly oszczędza godziny próby
   disassemblowania x86-64.
2. **Stringi to złoto** — w .NET stringi są UTF-16, więc trzeba wyciągać oba
   formaty. Komunikaty błędów często zdradzają warunki walidacji.
3. **Nazwy metod są zachowane** — w .NET (jeśli nie ma obfuskatora) widać
   `ComputeSerial`, `ShiftSerial` itd., co od razu kieruje analizę.
4. **Refleksja > emulacja** — szybciej skompilować mały loader i użyć
   `Assembly.LoadFrom` + `GetMethod().Invoke()` niż implementować logikę
   ponownie i ryzykować subtelne różnice (np. zachowanie `conv.u1`).
5. **`/` vs `==`** — gdy widzisz dzielenie całkowite w warunku, sprawdzaj cały
   zakres, nie tylko punkt — może być wiele rozwiązań. W tym CrackMe to luka
   designu, ale dobrze ją zauważyć.
