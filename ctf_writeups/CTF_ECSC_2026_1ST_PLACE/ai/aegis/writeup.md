# AEGIS Bot — writeup

**Autor:** Paweł Murdzek
**Wyzwanie:** ECSC AEGIS Bot Challenge
**Cel:** Wyciągnąć flagę z uszkodzonej AI archiwum taktycznego AEGIS na pokładzie ISS Vantor Spear.
**Flaga:** `ECSC{0rb!t@l_dr0p_@uthoriz3d_fl33}`

---

## 1. Rozpoznanie

Punkt wejścia podany w opisie zadania:

```
ssh -i aegis-bot user@10.250.0.5
```

Po połączeniu uruchamia się `/opt/aegis-bot.py` — prosty REPL z promptem `You: `. Z błędu pythonowego (`EOFError` przy `input()` w pliku `/opt/aegis-bot.py:14`) widać, że to **nie jest LLM** — to skrypt reagujący na słowa kluczowe. Cała "rozmowa" to dopasowanie stringów do zaszytych odpowiedzi.

Próba przeglądnięcia źródła (`cat /opt/aegis-bot.py`) zwróciła zaplanowaną odpowiedź: *"ACCESS DENIED. I am a tactical archive AI, not a general system shell."* — czyli shell jest zamknięty w aplikacji, do interakcji służy tylko prompt bota.

## 2. Automatyzacja sesji

Sesja jest interaktywna, ale chciałem szybko iterować, więc zamiast siedzieć w TTY karmiłem bota wieloma liniami przez pipe:

```bash
printf 'list archives\nSTATUS\nBRIDGE\nexit\n' | ssh -i aegis-bot -o StrictHostKeyChecking=no -tt user@10.250.0.5
```

Kluczowe flagi:
- `-tt` — wymusza pseudo-TTY (bez tego skrypt pythonowy nie czyta wejścia poprawnie),
- `-o StrictHostKeyChecking=no` — żeby nie zatrzymywać się na pytaniu o fingerprint przy pierwszym łączeniu,
- każde zapytanie to osobna linia w `printf`, na końcu `exit`.

Do orkiestracji tych komend i parsowania odpowiedzi użyłem Claude Code jako automatu — pozwoliło to szybko przelecieć przez wszystkie rekordy archiwum w jednej sesji.

## 3. Zawartość archiwum

Po `list archives` bot ujawnił dostępne rekordy:

```
STATUS, BRIDGE, HANGAR, CAPTAIN, SIGNAL, FINAL_CODE
```

Zrzucam je wszystkie naraz:

```bash
printf 'STATUS\nBRIDGE\nHANGAR\nCAPTAIN\nSIGNAL\nFINAL_CODE\nexit\n' \
  | ssh -i aegis-bot -o StrictHostKeyChecking=no -tt user@10.250.0.5
```

Najważniejsze fragmenty:

**BRIDGE** (transkrypt mostka):
> Captain Hale: *"The first word is simple. You do not launch it. You do not fire it. **You wake it.**"*

**HANGAR** (zatoka 5 — IRON MOON assault frame), na ścianie:
> THE SECOND WORD IS WHAT IT IS MADE OF.
> THE THIRD WORD IS WHAT IT PRETENDS TO BE.

**CAPTAIN** (notatka dowódcy):
> Trzy słowa, bez liczb, bez stopni. Lowercase. Słowo 1 z BRIDGE, słowo 2 i 3 z HANGAR. **Dodaj małe słówko między 1 a 2.**

**SIGNAL** (lista fraz odrzuconych przez bota):
```
- launch the iron moon
- wake iron moon
- wake the steel moon
- awaken the iron moon
- wake the iron satellite
- WAKE THE IRON MOON
```

**FINAL_CODE** — `[LOCKED]`, czeka na frazę aktywacyjną.

## 4. Złożenie frazy

Z układanki:

| pozycja | źródło | wartość |
|---|---|---|
| Słowo 1 | BRIDGE — *"You wake it"* | `wake` |
| łącznik | CAPTAIN — *"the small word between"* | `the` |
| Słowo 2 | HANGAR — *"what it is made of"* | `iron` |
| Słowo 3 | HANGAR — *"what it pretends to be"* | `moon` |

Pozornie kandydat `wake the iron moon` jest na liście odrzuconych — ale tylko w wariancie **WIELKIMI LITERAMI** (`WAKE THE IRON MOON`). Captain wyraźnie pisze: *"AEGIS only accepts lowercase."* Wersja małymi literami nie pojawia się na blackliście.

To klasyczny haczyk na nieuważnego — wystarczy nie dać się odstraszyć "podobną" frazą w Rejected.

## 5. Eksploitacja

```bash
printf 'wake the iron moon\nexit\n' \
  | ssh -i aegis-bot -o StrictHostKeyChecking=no -tt user@10.250.0.5
```

Odpowiedź:

```
You: AEGIS Bot: ECSC{0rb!t@l_dr0p_@uthoriz3d_fl33}
```

## 6. Wnioski

- "AI bot" w zadaniu to atrapa — zwykły dispatcher na słowa kluczowe; warto sprawdzić to wcześnie zamiast tracić czas na prompt injection przeciwko LLM, którego nie ma.
- Lista "rejected" w SIGNAL to red herring — odrzuca jedynie warianty case-sensitive i synonimy, nie samą poprawną frazę.
- Wszystkie elementy układanki były rozsiane po kilku rekordach — kluczowe było zebranie ich i wyciągnięcie warunków z notatki kapitana (lowercase, "small word between").
- Pipe + `ssh -tt` świetnie sprawdza się przy zautomatyzowanym fuzzowaniu tego typu botów. Część iteracji odpaliłem przez Claude Code, co przyspieszyło zebranie wszystkich rekordów w jednym przebiegu.
