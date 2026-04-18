# Writeup: Lokalizacja punktu na podstawie zdjęć drzew (Kampus PG)

**Autor:** Paweł Murdzek  
**Kategoria:** OSINT / Geo-location  
**Cel:** odnalezienie ukrytego punktu na podstawie trzech zdjęć drzew z kampusu Politechniki Gdańskiej i wyznaczenie środka ich układu.

## Wstęp

Zadanie polegało na zidentyfikowaniu trzech konkretnych drzew na terenie kampusu Politechniki Gdańskiej na podstawie dostarczonych fotografii, zdobyciu ich współrzędnych geograficznych, a następnie obliczeniu z nich tzw. środka ciężkości (centroidu).

Do dyspozycji były:
- 3 zdjęcia,
- otwarta Baza Drzew Politechniki Gdańskiej (interaktywna mapa GIS / inwentaryzacja zieleni kampusu).

## Krok 1: Analiza zdjęć i identyfikacja gatunków (OSINT przyrodniczy)

Aby skutecznie przeszukiwać bazę, najpierw trzeba było rozpoznać gatunki drzew.

### 1) `smolTree.jpg`

Na zdjęciu widać zbliżenie na pień i gałęzie z pękającymi, dużymi pąkami (wczesna wiosna). Kora jest spękana w charakterystyczne, łuskowate płaty. Kształt pąków i wyłaniających się z nich liści wskazuje na **kasztanowca pospolitego** (*Aesculus hippocastanum*).

### 2) `barkTree.jpg`

To zdjęcie dało najwięcej punktów odniesienia:
- **Drzewo:** głęboko, siateczkowato spękana kora; wygląd typowy dla **robinii akacjowej** (*Robinia pseudoacacia*), potocznie „akacji”.
- **Tło (geolokalizacja):** charakterystyczny gmach z czerwonej cegły, duże łukowate okna i specyficzny dach; architektura typowa dla starszej części kampusu PG.
- **Detal:** tabliczka orientacyjna hydrantu `H 80`, potencjalnie pomocna przy pracy z mapami infrastruktury (np. Geoportal).

### 3) `coolTree.jpg`

Potężne drzewo iglaste z płaskimi łuskami zamiast klasycznych igieł. Pokrój i układ gałęzi sugerują **żywotnika olbrzymiego** (*Thuja plicata*) lub **cyprysika** (*Chamaecyparis*).

## Krok 2: Praca z Bazą Drzew Politechniki Gdańskiej

Po identyfikacji gatunków nastąpiło przeszukiwanie bazy drzew PG.

Wykonane działania:
- **Filtrowanie:** wybranie okazów kasztanowców, robinii i cyprysików/żywotników.
- **Korelacja z mapą:** szukanie miejsc, gdzie robinia rośnie w odpowiedniej relacji do budynku z czerwonej cegły (zgodnie z perspektywą ze zdjęcia `barkTree.jpg`).
- **Ekstrakcja danych:** odczytanie dokładnych współrzędnych trzech zidentyfikowanych drzew.

Odnalezione koordynaty:
- **Drzewo 1 (Kasztanowiec):** `54.370586, 18.620963`
- **Drzewo 2 (Robinia):** `54.3724318, 18.6178464`
- **Drzewo 3 (Iglak):** `54.3712186, 18.6171353`

## Krok 3: Obliczenie współrzędnych docelowych

Zgodnie z poleceniem, poszukiwany punkt to środek trójkąta wyznaczonego przez trzy drzewa (centroid). Obliczenie polega na wyznaczeniu średniej arytmetycznej szerokości (`latitude`) i długości (`longitude`) geograficznej.

Obliczenia:

- **Szerokość (N):**  
  `(54.370586 + 54.3724318 + 54.3712186) / 3 = 54.3714121`  
  (uwaga: system sprawdzający ostatecznie zaakceptował wartość `54.3713`)

- **Długość (E):**  
  `(18.620963 + 18.6178464 + 18.6171353) / 3 = 18.6186482`

Wymagany format końcowy: 4 miejsca po przecinku.

Przyjęte współrzędne końcowe:
- **Latitude:** `54.3713`
- **Longitude:** `18.6186`

## Flaga / wynik końcowy

Zgodnie z formatem odpowiedzi:

`ping{54.3713, 18.6186}`

Sprawdzenie punktu w Google Maps prowadzi do centrum kampusu Politechniki Gdańskiej (okolice WETI). Zadanie rozwiązane.