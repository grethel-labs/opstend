# 10 · Fünf optionale Ausbaustufen nach RC2

Stand 2026-11-24. Die Reihenfolge folgt dem [Fahrplan bis RC2](../../post-rc1.md)
und der [Abnahme](08-delivery-and-iterations.md). Jede Ausbaustufe liefert
einen abgeschlossenen, belegbaren Umfang. Vor Beginn wird anhand der
RC2-Ergebnisse entschieden, welche Optionen und Plattformen konkret
priorisiert werden. Die folgenden Gates führen keine RC2-Pflicht ein.

## 1 · Betriebsstabilität und wiederholbare Wiederherstellung

**Auslöser**: RC2 auf einer gemischten Flotte akzeptiert und regelmäßig
benutzt. Ein Recovery-Pfad dauert zu lange, hat blinde Abhängigkeiten oder
braucht wiederholt manuellen Abgleich.

| Vergleich | Ansatz für diese Stufe |
|---|---|
| Mehr Funktionen gegen besser wiederholbare Release-/Recovery-Drills | Erst Upgrade, Import, Credentialrotation, Wiederherstellung und Deduplizierung auf zwei aufeinanderfolgenden Releases reproduzieren. |
| Manuell wiederkehrender Runbook-Drill gegen vollständig automatisches Produktions-Failover | Automatisierte Sandbox-Vorbereitung und Prüfung. Produktiver Wechsel hat weiterhin bestätigte Autorität und dokumentierte Bedingungen. |
| Lokale Aufbewahrung gegen unabhängige, getrennte bzw. unveränderliche Kopie | Eine zusätzliche Repositories-/Datastore-Variante nach beobachtetem Bedarf testen. IAM, Transport und Lifecycle-Regeln gegen echten Restore prüfen. |

**Umfang:** Diagnose-Ansicht für unerledigte Taskzustände, klar
gescopter Operator-Reconcile, Recovery der Steuerung nach Schlüsselrotation,
zeitgebundene Backup-Deckung und laufende Kapazitätsmessungen. Bei
S3 mit Object Lock hängt der Schutz von Aufbewahrung an Objektversionen,
Scope und Delete-Rechten. Kompatibilität mit Prune und PBS-Chunks wird
am genauen Backend geprüft. [PBS S3 Storage](https://pbs.proxmox.com/docs/storage.html) ·
[S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)

**Abnahme:** Zwei Wiederholungen des getesteten Release-/Rollback-Pfads,
zwei unabhängige Restore-Drills mit dokumentiertem fachlichem Ergebnis
und nachgewiesene Zielerreichung bei den in RC2 definierten Szenarien.
Fehlerberichte werden aus prüfbaren Evidence-Links erzeugt.

## 2 · Weitere Hardware, Telemetrie und Adapter

**Auslöser**: Betreiber wollen einen konkreten zusätzlichen Plattform-,
NAS- oder Gerätescope betreiben. Der Adapter löst eine beobachtete
Sicht-/Bedienungslücke der heterogenen Flotte.

| Option | Schwerpunkt und Entscheidung |
|---|---|
| Pi agentenlos weiterführen oder nativen Arm64-Agenten betreiben | Agentenlos verursacht weniger Betrieb und eignet sich für Status und Kapazität. Ein nativer Agent lohnt bei konkretem Bedarf an sicherer lokaler Aktion und eigener Host-Evidenz. |
| Eingebautes Dashboard oder vorhandene Observability-Sammlung | Integrierte Projektion bleibt Bedienpfad. Prometheus-/OTel-Anbindung für längere Zeitachsen oder mehr Quellen nach realer Last. [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) |
| Topologie über Konfiguration, L2-Nachbarn oder echte Flows | Bestehende Provenienz erhalten. Ein L2- oder Flow-Adapter bleibt lesend, gekennzeichnet und auf einen registrierten Beobachtungsbereich begrenzt. Hubble ist ein Beispiel für eine plattformspezifische Kubernetes-Flow-Quelle. [Hubble Dokumentation](https://docs.cilium.io/en/stable/observability/hubble/) |
| Nativ mehr Plattformprofile gleichzeitig oder nacheinander | Je Betriebssystem/Architektur eine testbare Kombination. PVE Arm64, Steward Linux Arm64 und ein NAS-Adapter erhalten getrennte Supportzeilen. [PVE Arm64 Plattformhinweise](https://forum.proxmox.com/threads/proxmox-virtual-environment-now-available-for-64-bit-arm-arm64.185526/) |

**Umfang:** Eine zusätzliche reale OS-/Architektur-Kombination nach
S02-Verfahren oder ein primär benötigter Geräteadapter, plus der
kleinste benötigte Datenausgang. Geräte- oder Appliance-Schreiben
setzt eine eigene registrierte Aktion, minimale Rolle, native Quittung
und Rückweg voraus. Eine verlässlich registrierte Außenschnittstelle
kann ihr Schema über OpenAPI dokumentieren. [Steward OS-Profile](../repositories-release.md#s02--add-one-osarchitecture-profile-at-a-time) ·
[OpenAPI Initiative](https://openapis.org/what-is-openapi/)

**Abnahme:** Signierter Installationspfad auf der konkret unterstützten
Plattform, erneute Anwendung, Reboot, Isolation, Scope und Beobachtungen.
Neue Telemetrie erhält einen Last-, Cardinality- und Rechtevergleich
mit dem RC2-Ausgangswert.

## 3 · Lifecycle über getrennte PVE-Instanzen

**Auslöser**: Wiederholte Betreiberaufträge für Standortumzug, geplante
Wiederherstellung auf einem Einzelhost oder Umschichtung zwischen
PVE-Instanzen.

| Ansatz | Wirkung und Grenze |
|---|---|
| Backup zu isoliertem Restore, danach geplanter Cutover | Gut belegbar mit neuer Gastidentität und geprüfter Nutzlast. Pause und Datenalter müssen passen. |
| Native kalte Verlagerung | Geeignet bei belegten PVE-Versionen und akzeptiertem Wartungsfenster. Rechte, Storage- und Netzwerkzuordnung müssen zusammenpassen. |
| Native Live-Migration außerhalb einer PVE-Instanz | Interessant bei engem RTO. PDM unterstützt diese Fähigkeit für passende PVE-Remotes. CPU-/Versionen, Geräte, Datendurchsatz und Abbruchpfad bestimmen die Steward-Freigabe. [PDM Remotes](https://pdm.proxmox.com/docs/remotes.html) |

**Umfang:** Zuerst Restore und kontrollierte Umschaltung für genau
eine festgelegte Quell-/Zielkombination. Der Plan bindet Reservierungen,
neue Identität oder belegte Kontinuität, RPO/RTO, beide Sicherheits-
rahmen, Netzwerkübersetzung und den Rollback-Vertrag. Alte und neue
Schreibpfade wechseln mit eindeutigem Eigentümer. Aufnehmen einer
weiteren PVE-Cluster-Mitgliedschaft wird als eigener Betreiberpfad
geprüft.

**Abnahme:** Je ein kontrollierter Durchlauf und ein Abbruch auf
realen Zielinstanzen. Nutzdatenprüfung vor Auslieferung, eindeutige
Zielzuordnung, verifizierter alter Pfad und sichtbare Wirkung bei
einem Konflikt. Clusterübergreifende Live-Migration erhält erst nach
eigenem Beleg eine Capability.

## 4 · Mehrere Standorte und getrennte Vertrauensdomänen

**Auslöser**: Es gibt einen zweiten Standort mit realem Zielinventar,
eigenem Netz-/Speicherpfad und belegter administrativer Zuständigkeit.
Ein Betreiber braucht bei Standortverlust einen kürzeren
Wiederherstellungsweg als im RC2-Verfahren.

| Modell | Stärken | Grenze |
|---|---|---|
| Externer Wiederaufbau aus Snapshot | Wenige Komponenten; reproduzierbare Wiederherstellung in neuer Generation | RTO umfasst den unabhängigen Wiederaufbau und den alten Pfadabgleich. |
| Vorbereitete externe Kalt-/Warm-Steuerung mit manueller Übernahme | Infrastruktur und getestete Recovery-Identität verfügbar, flexibleres RTO | Alte Site muss wirksam isoliert, vorhandene Aktionen müssen abgeglichen werden. |
| Unabhängige Site-Autoritäten mit zentraler Lesesicht | Jede Site kann lokal fortarbeiten. Berechtigung und Eigentümer bleiben standortbezogen. | Site-übergreifende Sammelaktionen benötigen jeweils explizite Autorisierungen und per-Site-Resultate. |
| Ein aktiv schreibendes WAN-Quorum | Konsistente Entscheidungen für ein explizit dafür ausgelegtes Netzwerk | Schreibzeiten hängen von WAN-Latenz und Platzierung der Mehrheit ab. Komplexe Partitionen sowie Credential- und Zugangsabhängigkeiten brauchen Vorrang vor Failover-Automatisierung. [etcd Fehlermodell](https://etcd.io/docs/v3.6/op-guide/failures/) |

**Umfang:** Zunächst externe Warm-Recovery-Option oder unabhängige
Site-Autoritäten entsprechend dem nachgewiesenen Bedarf. Eine
öffentliche oder organisationsweite Admin-Schnittstelle übernimmt die
S03-Gates. OIDC liefert Identität und Sitzungskontext. Scope, lokale
Executor-Grenzen, Revocation und verbundweiter Job-Claim bleiben eigene
Steward-Entscheidungen. SCIM kann später Identitätsbereitstellung
ergänzen, wenn Zielorganisationen sie brauchen.
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) ·
[SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644.html)

**Abnahme:** WAN-Partition während eines Auftrags, zeitweise getrennter
Identitätsdienst, simuliertes vollständiges Standortversagen und
Rückkehr des alten Standorts. Erlaubte egress- und credentialgebundene
Pfade und eine exklusive Schreibeautorität werden belegt.
Automatische Standortübernahme setzt eine eigene Methodik für
nachweisbares externes Fencing und Berechtigungswechsel voraus.

## 5 · Weitere dynamische Dienste und hardwaregebundene KI

**Auslöser**: CPU-, Speicher- oder Schlüsselgrenzen rechtfertigen die
Verlagerung weiterer Steward-Rollen. Die Steuerung und Backup-Planung
haben den CP03-Ausfalltest stabil bestanden.

| Rolle | Eigenes Daten- und Freigabemodell |
|---|---|
| Scanner | Images und Ziel-Runtime gebunden, großer Cache außerhalb des Quorums, isolierter Datenaustausch, aktuelle Ergebnisse pro Ressourcengeneration |
| Builder / Validator | Getrennte Vertrauensdomänen; kurzlebige Workspaces, unveränderliches Digestergebnis, keine gemeinsame Admin-Identität und kein Produktionsdeployment durch den Builder |
| Beelink-Inferenz | Freigegebenes Treiber- und Geräteprofil, eigener Modell-Cache, reservierter RAM und Hostbindung, Health- und Budgetnachweis |
| Weitere optionale Worker | Eigene Idempotenz, Jobfristen, Drain und Fencing für ihren tatsächlichen Wirkungsbereich |

**Umfang:** Genau eine neue Rolle pro validierter Ausbaurunde. Wenn
ein zweiter geeigneter KI-Host existiert, ist ein vorbereitetes
Ersatzprofil möglich. Reproduzierbare Modellreferenzen und ein
belegter Cache erleichtern Übernahme. KI bleibt optional;
Berechtigung, Gast-HA, Wiederherstellung und Deterministik nutzen
weiter die regulären Verträge.
[Linux-/KI-Profil](05-linux-devices-and-ai.md) · [Steward HA](07-steward-ha.md) ·
[KI-Arbeitspakete](../ai.md)

**Abnahme:** Ein konkreter Workload, reale Ressourcen-/Isolationsprobe,
kontrollierte Unterbrechung, kein doppelter Auftrag und verständliche
Degradierung ohne passenden Ersatzkandidaten. Die Support-Matrix
nennt die wiederanlaufbaren Rollen samt Hardware und Version.

## Priorisierung und Stopppunkte

Betriebsstabilität kommt zuerst. Weitere Hardware und Lifecycle werden
bei nachgewiesenem Bedarf ausgebaut. Standort-Recovery und neue
dynamische Rollen setzen die belegte Exklusivität des betroffenen
Schreibpfads voraus. Für jede Runde werden Ziel, Freigabeevidenz und
fixer Scope vor Beginn entschieden. Neue Produktfragen werden als
eigenständiger Folgepunkt dokumentiert. Ein fertiger Release-Stand
bleibt im bestehenden Betriebsprofil benutzbar.
