# Pod Hunter — writeup

**Autor:** Paweł Murdzek
**Kategoria:** DevSecOps / Kubernetes
**Format flagi:** `ecsc{...}`
**Flaga:** `ecsc{DEVOPSTOOLS#123Fsdnk.$#@43}`

---

## Opis zadania

W katalogu `pod-hunter` dostałem jeden plik — `config1`. Kubeconfig dla klastra Kubernetes. Cel: znaleźć flagę ukrytą "w pliku wewnątrz poda". Brzmiało prosto — okazało się najdłuższym zadaniem całego zestawu, pełnym pułapek i fałszywych tropów.

---

## Rekonesans

### Tożsamość i uprawnienia

```bash
export KUBECONFIG=./config1
kubectl auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:pod-hunter:player
Groups      [system:serviceaccounts system:serviceaccounts:pod-hunter system:authenticated]
```

```bash
kubectl auth can-i --list -n pod-hunter
```

```
Resources   Verbs
pods        [get list]
```

To wszystko. Jedno uprawnienie: `get` i `list` na **pods** w namespace `pod-hunter`. Żadnych secretów, configmapów, deploymentów — czyste RBAC lockdown. Wszystkie inne zasoby zwracają `Forbidden`.

### Listowanie podów

```bash
kubectl get pods -n pod-hunter -o wide
```

```
NAME   READY   STATUS    RESTARTS       AGE   IP             NODE
pod2   1/1     Running   52 (50m ago)   9d    172.16.1.91    worker01
pod4   1/1     Running   52 (50m ago)   9d    172.16.1.129   worker01
pod5   1/1     Running   52 (50m ago)   9d    172.16.1.74    worker01
```

Trzy pody, wszystkie na `worker01` (10.250.3.2), wszystkie działają od 9 dni z ponad 50 restartami. Działają jako `default` SA, obraz `busybox`, polecenie `sleep 3600`. Pobieram pełne specki:

```bash
kubectl get pod pod2 pod4 pod5 -n pod-hunter -o json
```

---

## Pułapka #1 — zmienne środowiskowe z nazwami miast

W specyfikacjach podów uwagę przykuwa zmienna środowiskowa `ELO`:

| Pod  | ELO                  |
|------|----------------------|
| pod2 | `BYDGOSZCZ_JAZDA`    |
| pod4 | `KRAKOW_JAZDA`       |
| pod5 | `SZCZECIN_JAZDA`     |

Trzy polskie miasta. W CTF-ach czasem flaga jest w nazwie — próba `ecsc{BYDGOSZCZ_KRAKOW_SZCZECIN}`: **Incorrect**. Próba samych wartości: bez sensu. To dekoracja — klasyczny red herring.

---

## Pułapka #2 — pod logs

Skoro flaga jest "w pliku wewnątrz poda", pierwsza myśl: logi.

```bash
kubectl auth can-i get pods/log -n pod-hunter
```

```
yes
```

Wygląda obiecująco. Ale:

```bash
kubectl logs pod2 -n pod-hunter
```

```
Error from server (Forbidden): pods "pod2" is forbidden: User "system:serviceaccount:pod-hunter:player"
cannot get resource "pods/log" in API group "" in the namespace "pod-hunter"
```

`auth can-i` pokazuje `yes` — fałszywy alarm. To znany artefakt Kubernetes: dla subzasobów (`pods/log`) `can-i` sprawdza uprawnienie do rodzica (`pods`) i może zwrócić `yes` nawet gdy faktyczny dostęp do subzasobu jest oddzielnie zablokowany. Prawdziwy RBAC sprawdza się tylko próbą realnego żądania.

---

## Pułapka #3 — Kubelet API

Wszystkie pody siedzą na `worker01`. Kubelet nasłuchuje na porcie 10250. Może bezpośredni dostęp do kubelet API pozwoli obejść RBAC i wykonać polecenie w podzie?

```
GET https://10.250.3.2:10250/exec/{namespace}/{pod}/{container}
```

Kubelet wymaga uprawnienia `nodes/proxy` na poziomie ClusterRole — do **każdej** swojej operacji. Próba z tokenem `player`:

```
HTTP 403: Forbidden — cannot create resource "nodes/proxy"
```

Próba z tokenem `default` SA (wyciągniętym przez API): to samo. Kubelet API jest skutecznie zablokowany.

---

## Pułapka #4 — eskalacja przez inne zadanie (znaleziona zła flaga)

Mając dostęp do `config4` (zadanie `volume-flag`), player04 ma uprawnienia `create pods` i `pods/exec` w namespace `volume-flag`. Tworzę uprzywilejowany pod na `worker01` z `hostPath: /` — klasyczny container escape z poprzedniego zadania:

```bash
kubectl --kubeconfig ../volume-flag/config4 apply -f hunter-worker01.yaml
```

Z wnętrza poda przeszukuję cały filesystem hosta. Natrafiam na coś ciekawego — namespace `log-tracker` z podem `sys-worker-01`, który ma zamontowany secret `vol-secret` zawierający plik `data.bin`. Czytam go:

```bash
kubectl exec -n volume-flag hunter-worker01 -- \
  sh -c 'cat /host/var/lib/kubelet/pods/.../volumes/kubernetes.io~secret/vol-secret/data.bin'
```

```
ecsc{logs-are-noise^tkcmGf234}
```

Radość — aż do momentu zgłoszenia: **Incorrect**.

Ta flaga należy do **innego zadania** (prawdopodobnie `log-tracker`), które nie jest częścią zestawu. Twórcy specjalnie umieścili ją w zasięgu, żeby zwabić kogoś, kto ucieknie z namespace przez eskalację uprawnień. Lekcja: nie szukaj flagi tam, gdzie nie powinieneś mieć dostępu.

---

## Właściwe rozwiązanie — pody rotują

Wracam do punktu wyjścia: `get/list pods`. Tym razem uruchamiam listowanie z jawnym pustym field-selectorem, żeby pokazać wszystkie pody niezależnie od fazy:

```bash
kubectl get pods -n pod-hunter --field-selector='' -o wide
```

```
NAME   READY   STATUS    RESTARTS       AGE     IP             NODE
pod1   1/1     Running   0              8m9s    172.16.2.52    worker02
pod2   1/1     Running   53 (15m ago)   9d      172.16.1.91    worker01
pod3   1/1     Running   0              8m8s    172.16.2.117   worker02
pod4   1/1     Running   53 (15m ago)   9d      172.16.1.129   worker01
pod5   1/1     Running   53 (15m ago)   9d      172.16.1.74    worker01
```

**Pod1 i pod3 — nowe, na worker02, właśnie weszły w życie (8 minut temu, restartCount: 0).** Wcześniej nie były widoczne, bo jeszcze nie istniały lub były już zakończone. Zestaw podów w namespace rotuje się — co jakiś czas pojawiają się nowe instancje z różnymi właściwościami.

Pobieram specki:

```bash
kubectl get pod pod1 pod3 -n pod-hunter -o json
```

Pod1: zmienna `ELO = RADOM_JAZDA` — kolejny decoy.

Pod3:

```json
{
    "name": "ELO",
    "value": "ecsc{DEVOPSTOOLS#123Fsdnk.$#@43}"
}
```

Flaga w zmiennej środowiskowej `ELO` poda `pod3`. Właśnie po to są `get/list pods`.

---

## Flaga

```
ecsc{DEVOPSTOOLS#123Fsdnk.$#@43}
```

---

## Mechanizm zadania — pełny obraz

Namespace `pod-hunter` zawiera dwie grupy podów:

**Pody-przynęty (worker01, żyją 9+ dni, ciągłe restarty):**
- pod2 → `ELO=BYDGOSZCZ_JAZDA`
- pod4 → `ELO=KRAKOW_JAZDA`
- pod5 → `ELO=SZCZECIN_JAZDA`

**Pody rotujące (worker02, żyją ~1h):**
- pod1 → `ELO=RADOM_JAZDA` (decoy)
- pod3 → `ELO=ecsc{DEVOPSTOOLS#123Fsdnk.$#@43}` ← flaga

Pod3 startuje, żyje godzinę (`sleep 3600`), kończy się i po chwili pojawia się ponownie z tym samym contentem. Pody na worker01 mają identyczny cykl, ale zawsze te same wartości-śmieciowe.

Zamierzony tok myślenia:
1. Masz tylko `get/list pods` — nie potrzebujesz nic więcej.
2. Pody mają zmienne środowiskowe — czytasz je przez `kubectl get pod -o json`.
3. Ale nie listowałeś w odpowiednim momencie. Czekaj albo listuj ponownie.
4. Pod3 to właśnie ten pod, który szukałeś.

---

## Narzędzia

| Narzędzie | Zastosowanie |
|-----------|-------------|
| `kubectl` | Jedyne narzędzie potrzebne do rozwiązania |

---

## Wnioski i lekcje

1. **`get/list pods` to potężne uprawnienie.** Pod spec jest dokumentem — zawiera obrazy, polecenia, zmienne środowiskowe, wolumeny, adnotacje. Wszystko to może być wektorem wycieku danych.

2. **Środowisko nie jest statyczne.** Pody mogą rotować, być tworzone i usuwane. Jednorazowe listowanie daje tylko chwilowy obraz stanu klastra. Przy zadaniach "znajdź flagę" warto listować kilkukrotnie lub obserwować zmiany przez `kubectl get pods -w`.

3. **Nie szukaj tam, gdzie nie masz dostępu.** Jeśli przyszło ci do głowy "a może użyję uprawnień z innego zadania" — to prawdopodobnie pułapka. Zadanie jest skonstruowane tak, żeby dawało się je rozwiązać w jego własnym zakresie RBAC.

4. **`auth can-i` kłamie dla subzasobów.** `can-i get pods/log` zwróciło `yes`, ale rzeczywiste żądanie dało `403`. Zawsze weryfikuj realnym wywołaniem.

5. **Env vars to nie tylko konfiguracja.** W Kubernetes zmienne środowiskowe kontenerów są widoczne dla każdego, kto może `get pod`. Wrażliwe dane (hasła, tokeny, flagi) nie mają tam miejsca — każdy z `get pods` w namespace je przeczyta.

---

## One-liner

```bash
kubectl --kubeconfig ./config1 get pods -n pod-hunter \
  --field-selector='' -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .spec.containers[*].env[*]}{.name}{"="}{.value}{"\n"}{end}{end}'
```

```
pod1    ELO=RADOM_JAZDA
pod2    ELO=BYDGOSZCZ_JAZDA
pod3    ELO=ecsc{DEVOPSTOOLS#123Fsdnk.$#@43}
pod4    ELO=KRAKOW_JAZDA
pod5    ELO=SZCZECIN_JAZDA
```
