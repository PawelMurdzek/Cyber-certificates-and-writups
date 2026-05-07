import scipy.io.wavfile as wav
import math

# 1. Wczytanie "jednowymiarowej siatki"
# Upewnij się, że nazwa pliku się zgadza
rate, data = wav.read("blinking.wav")

# Rozdzielenie kanałów ("Dolina Królów" = Lewy/Zachodni, "Luksor" = Prawy/Wschodni)
left_channel = data[:, 0]
right_channel = data[:, 1]

flag = ""

# 2. "Zagrać z nim w oczko" -> Krok co 21 próbek
for i in range(0, len(left_channel), 21):
    
    # 3. "Wyznacz różnicę"
    diff = left_channel[i] - right_channel[i]
    
    # 4. "Nil dzieli" (długość 6650) oraz "szukaj na podłodze" (math.floor)
    # Jeśli 6650 nie zadziała, spróbuj 6695
    ascii_val = math.floor(diff / 6650)
    
    # Zamiana wartości numerycznej na znak tekstowy
    # Sprawdzamy czy to sensowny znak ASCII (zakres liter/cyfr) by odrzucić szum
    if 32 <= ascii_val <= 126:
        flag += chr(ascii_val)

print("Znaleziona flaga to:")
print(flag)