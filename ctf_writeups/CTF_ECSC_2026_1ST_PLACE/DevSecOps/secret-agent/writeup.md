# CTF Writeup — Secret Agent

**Kategoria:** DevSecOps / Kubernetes  
**Autor rozwiązania:** Paweł Murdzek  
**Data:** 2026-05-06  
**Flaga:** `ecsc{tls_trick_L36_K0KS13^}`

---

## Opis zadania

Dostałem dostęp do katalogu projektu `secret-agent`. Moim zadaniem było odnalezienie ukrytej flagi. Brzmiało prosto — ale jak się okazało, twórcy zadania zadbali o kilka pułapek po drodze.

---

## Rekonesans — co mamy w katalogu?

Zaczynam od przejrzenia zawartości katalogu roboczego:

```bash
ls -la
```

```
-rw-r--r-- 1 pawel 197609 2765 May  6 09:49 config2
```

Jeden plik — `config2`. Otwieram go:

```bash
cat config2
```

Od razu widać, że to **kubeconfig** — plik konfiguracyjny dla klastra Kubernetes. Zawiera:

- **Adres serwera API:** `https://10.250.3.1:6443`
- **Namespace:** `secret-agent`
- **Użytkownik:** `player02`
- **Token JWT** do uwierzytelnienia

To jest mój punkt wejścia. Mam konto `player02` z tokenem serwisowym. Czas sprawdzić, co mogę z tym zrobić.

---

## Sprawdzanie uprawnień

Pierwsza rzecz po uzyskaniu tokenu w Kubernetes — sprawdzić, jakie mam uprawnienia. Używam `kubectl` z tym plikiem jako kubeconfig:

```bash
kubectl --kubeconfig config2 auth can-i --list -n secret-agent
```

Wynik:

```
Resources                                       Verbs
secrets                                         [get list]
selfsubjectaccessreviews.authorization.k8s.io   [create]
...
```

Mam `get` i `list` na **secrets** w namespace `secret-agent`. Bingo — to jedyna ciekawa uprawnienie. Próba listowania podów, deploymentów itd. kończy się `Forbidden`.

---

## Listowanie secretów

```bash
kubectl --kubeconfig config2 get secrets -n secret-agent
```

```
NAME             TYPE                                  DATA   AGE
flag             Opaque                                1      186d
newtls           kubernetes.io/tls                     2      186d
ok               Opaque                                1      186d
player02-token   kubernetes.io/service-account-token   3      140d
tls              kubernetes.io/tls                     2      186d
```

Mam pięć secretów. Najbardziej oczywiste cel to `flag` i `ok`. Zaczynam od nich.

---

## Pułapka #1 — secret `flag`

```bash
kubectl --kubeconfig config2 get secret flag -n secret-agent \
  -o jsonpath='{.data.flag}' | base64 -d
```

```
ecsc{TRY_HARDER}
```

Klasyczny honeypot. Flaga mówi wprost: szukaj dalej.

---

## Pułapka #2 — secret `ok`

```bash
kubectl --kubeconfig config2 get secret ok -n secret-agent \
  -o jsonpath='{.data.flag}' | base64 -d
```

```
ecsc{this_is_not_this_flag}
```

Kolejna pułapka. Twórcy zadania dali nam dwa fałszywe tropy, żeby odstraszyć niecierpliwych.

---

## Prawdziwy trop — sekrety TLS

Zostały dwa ciekawe obiekty: `tls` i `newtls` — oba typu `kubernetes.io/tls`. TLS secret normalnie przechowuje certyfikat i klucz prywatny. Ale co jeśli ktoś ukrył coś w samym certyfikacie?

Pobieram certyfikat z secretu `tls`:

```bash
kubectl --kubeconfig config2 get secret tls -n secret-agent \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > cert.pem
```

Teraz analizuję certyfikat narzędziem `openssl`:

```bash
openssl x509 -noout -text -in cert.pem | grep -E "Subject:|Issuer:|CN="
```

```
Issuer: CN=ecsc{tls_trick_L36_K0KS13^}
Subject: CN=ecsc{tls_trick_L36_K0KS13^}
```

Jest! Flaga zakodowana w polu **Common Name (CN)** certyfikatu X.509 — zarówno w Issuer, jak i Subject. Certyfikat jest self-signed, więc Issuer i Subject są identyczne.

To samo powtarza się w sekrecie `newtls` — identyczny certyfikat.

---

## Flaga

```
ecsc{tls_trick_L36_K0KS13^}
```

---

## Narzędzia użyte w zadaniu

| Narzędzie | Zastosowanie |
|-----------|-------------|
| `kubectl` | Interakcja z klastrem Kubernetes |
| `base64` | Dekodowanie danych z secretów |
| `openssl x509` | Analiza certyfikatu TLS |

---

## Wnioski i lekcje

1. **Oczywiste sekrety to pułapki.** Secret o nazwie `flag` to pierwsze miejsce, gdzie każdy zagląda — dlatego twórcy CTF właśnie tam umieszczają honeypot.

2. **Kubernetes TLS secret to więcej niż klucz i certyfikat.** Pola X.509 takie jak CN, SAN (Subject Alternative Name), OU czy O mogą przechowywać dowolny ciąg znaków. Certyfikat można wygenerować z flagą w CN bez żadnych ograniczeń.

3. **`auth can-i --list` to must-have** przy każdym zadaniu z Kubernetes. Pozwala szybko zmapować powierzchnię ataku bez zbędnych prób i błędów.

4. **Zawsze analizuj certyfikaty.** `openssl x509 -noout -text` ujawnia wszystkie pola certyfikatu — nie tylko klucz publiczny, ale też metadane, które mogą kryć niespodzianki.

---

## Pełny one-liner (dla niecierpliwych)

```bash
kubectl --kubeconfig config2 get secret tls -n secret-agent \
  -o jsonpath='{.data.tls\.crt}' | base64 -d | \
  openssl x509 -noout -subject
```

```
subject=CN=ecsc{tls_trick_L36_K0KS13^}
```
