# 01 · Proxmox nativ, Gastaktionen und Alternativen

Karten PX01–PX03 in [Proxmox](../proxmox.md). Stand der Recherche 2026-11-24.
Die Referenz nennt acht PVE-Hosts, davon drei im HA-Verbund. Dasselbe
Anschlussprofil ist bereits mit einem eigenständigen Host nützlich.
Produktentscheidungen gelten als Planung. Der unterstützte Versionsbereich
entsteht aus konkreten Nachweisen in PX01–PX03.

## Vergleich der Betriebs- und Integrationswege

| Option | Was sie abdeckt | Aufwand und Randbedingungen | Konsequenz für OpsTend |
|---|---|---|---|
| PVE-Weboberfläche und dokumentierte REST-API | Knoten, QEMU, LXC, Storage sowie administrative und asynchrone Operationen im nativen Modell | Der Client muss Tokenrechte, API-Dialekt, Ressourcenbezug und Task-Verlauf korrekt interpretieren. | PVE bleibt führend. OpsTend nutzt den REST-Vertrag und kann auf die native Oberfläche verweisen. [PVE API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/) |
| Proxmox Datacenter Manager | Zentrales Inventar mehrerer PVE- und PBS-Remotes, RRD, Gastaktionen, Migrationen auch zwischen Remotes und weitere PVE-Verwaltung | Gleichartiger Bereich wie OpsTend M9/M10. PDM besitzt eigene Registrierung, Rechte und Bedienung. | Geeigneter Vergleichsmaßstab und optional parallele Oberfläche. OpsTend liefert zusätzlich Linux-/Gerätebeziehungen, Richtlinien, Wiederherstellungsnachweise und eigene Dienstplatzierung. PDM ist keine laufende Abhängigkeit. [PDM Remotes](https://pdm.proxmox.com/docs/remotes.html) · [PDM Installation](https://pdm.proxmox.com/docs/installation.html) |
| Ansible `community.proxmox` | Deklarative Konfiguration und geplante Betreiber- oder CI-Arbeit für Gäste, Storage, HA und ACLs | Geeignet für reproduzierbare Labore. Die Ausführung folgt dem jeweiligen Playbook und seiner Identität. | Als Betreiberwerkzeug und für freigegebene Testvorbereitung geeignet. Interaktive Steward-Jobs bleiben beim registrierten, protokollierten Executor. [Ansible Collection](https://docs.ansible.com/ansible/latest/collections/community/proxmox/index.html) |
| OpenTofu mit einem PVE-Provider | Infrastruktur als Code mit Ressourcenzuordnung im State | Bestehende Ressourcen müssen importiert und Zuständigkeiten bei paralleler Bedienung geklärt werden. Native Fähigkeiten variieren mit dem Provider. | Extern deklarierte Ressourcen können übernommen oder beobachtet werden. Ein anderer Writer bleibt in der Zuständigkeitsansicht sichtbar. [OpenTofu State](https://opentofu.org/docs/language/state/) · [bpg/proxmox Provider](https://github.com/bpg/terraform-provider-proxmox) |
| Direktes `qm`/`pct`, `pvesh` oder Änderungen im Cluster-Dateisystem | Lokale Bedienung und Diagnose mit dem jeweiligen Privilegienkontext | Vergrößert die Reichweite einer generischen Remote-Ausführung und koppelt an Dateistrukturen oder CLI-Ausgaben. | Für Betreiber-Diagnose und unabhängigen Soll-Ist-Check. Remote-Anforderungen sind typisierte PVE-Aktionen mit registrierten IDs. [PVE Benutzerverwaltung](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) |

Ein gemischter Betrieb bleibt möglich. Für einen in OpenTofu verwalteten Gast
kann OpsTend zum Beispiel inventarisieren und dessen Wiederherstellung
prüfen. Provisionierung, Stromzustand und Zeitplan brauchen jeweils einen
explizit zuständigen Workflow. Die einmalige Übergabe ist in
[Flotte und Autorität](02-fleet-and-trust.md) beschrieben.

## Installationsprofile und Paketentscheidung

| Profil | Lokale Komponenten | Bevorzugter Einsatz |
|---|---|---|
| Nativer Einzelhost | Unprivilegierte Agent-Identität, optional eigene lokale Steuerung und SQLite, separat autorisierter API-Executor bei Schreibbedarf | Ein einzelner Host oder ein isolierter Pilot. Bedienung privat über lokal gebundene Schnittstelle. |
| Nativer Flottenagent | Beobachtung, ausgehender Transport und optional zielgebundene Exec-Identität. Ressourcengrenzen in eigenen Units. | Mehrere PVE-Hosts, lokale Diagnose und getrennte Vertrauensgrenzen. |
| API-only | Kein Paket am Ziel. Registrierter Connector in einem autorisierten Netz mit eigenen PVE-Tokens. | Bestehende PVE-Hosts mit Wunsch nach geringer Eingriffstiefe. |
| Separater Steuerhost | Steuerung in einer Management-VM oder auf geeignetem Linux. Anbindung über Agent oder Connector. | Mehrere Ziele. Weniger Abhängigkeit vom zu verwaltenden Hypervisor und gute Upgrade-Trennung. |

**Startentscheidung für PX01.** Eine signierte Release-Kette und ein
isoliertes, versioniertes Linux-Artefakt nutzen. Ein Debian-Paket ist ein
geeignetes Ziel, sofern Installieren, erneutes Anwenden, Upgrade und
Rückbau für jede Unit verlässlich abdeckbar sind. Ein signiertes Bundle mit
vorhandener Release-Verifikation und separater idempotenter Installationsrolle
ist eine zweite umsetzbare Variante, falls das Debian-Paket eine zusätzliche
Release-Kette erfordern würde. PX01 wählt genau einen unterstützten
Installationspfad und dokumentiert den Rückbau. Die Betreiberpakete und
PVE-Dienste bleiben unter PVE-Verantwortung.
[Debian Policy zu Installationsskripten](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) ·
[systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

- Eigene Unit-Namen, Dienstidentitäten, Zustandsverzeichnisse, Logs und
  Privilegien. Ein Unit-Update darf weder Hypervisor noch Gast neu starten.
- Keine unkontrollierte Abhängigkeit vom PVE-System-Python oder Änderungen an
  dessen Paketstand. Lokale Artefakte und Credential-Referenzen sind im Plan
  aufgelistet. Unit-Start und Paketinstallation haben getrennte Fehlerbilder.
- Ein Schutz auf systemd-Ebene ist Bestandteil der Abnahmematrix. Pfad-,
  Egress- und Identitätsgrenzen werden unter echter Dienstidentität geprüft.
  Eine lokal bindende API benötigt auch lokale Authentisierung.
- Preflight ermittelt belegte Ports, geplante Verzeichnisse, unterstütztes
  Betriebssystem, Architektur, API- und PVE-Paketversion, Erreichbarkeit,
  TLS und benötigte Rollen. Ein bekannter Installationskonflikt blockiert
  vor der ersten Änderung.
- Version 9.2 auf amd64 ist durch den dokumentierten Release-Stand eine
  sinnvolle erste Testfamilie. Die beobachteten Paketstände entscheiden über
  Freigabe und maximale Unterstützung. PVE für Arm64 mit expliziter
  Hardwareunterstützung und OpsTend auf Arm64 sind getrennte Prüfungen.
  Der Raspberry Pi ist im Referenzprofil NAS. PVE dokumentiert für die
  Arm64-Ausgabe eigene Plattformgrenzen.
  [PVE 9.2 Veröffentlichung](https://www.proxmox.com/en/about/company-details/press-releases/proxmox-virtual-environment-9-2) ·
  [PVE Arm64 Plattformhinweise](https://forum.proxmox.com/threads/proxmox-virtual-environment-now-available-for-64-bit-arm-arm64.185526/)

## API-Dialekt, Rechte und native Tasks

Eine Capability ist eine Kombination aus unterstützter Methode, Ziel,
Rechten, aktuell beobachteter Vorbedingung und Adapter-Version. Ein
PVE-Paketname, ein erfolgreicher TCP-Aufruf oder die Sicht auf eine Ressource
reichen allein für eine Freigabe nicht aus. Die erste Kompatibilitätsmatrix
wird aus dem API Viewer, dem Quellstand und den laufenden Testinstanzen
erstellt. Jede Zeile enthält HTTP-Operation, PVE-Version, Parameterumfang,
ACL-Pfad, erwartete Task-/Statusdaten und einen negativen Test.

| Pfad | Daten oder gewünschte Wirkung | Prüfpunkt |
|---|---|---|
| Inventar | PVE-Instanz, Knoten, Gäste, Tasks und sichtbar zugeordnete Storages/Netze | Rechteselektion und paginierte oder begrenzte Erfassung dokumentieren. Teilansicht erzeugt keine Löschung. |
| Gast-Lifecycle | Start, geordnetes Shutdown und Neustart eines freigegebenen Gastes | Frische Gastgeneration, native HA-Zuständigkeit, Node/Instanz und Zustandsvorbedingung prüfen. Kein Eskalieren von Shutdown zu Force Stop. |
| Provisionierung | QEMU-Klon aus registrierter Vorlage; Anlage eines LXC aus registriertem Container-Template | Pool, Ziel-Netz, Storage, VMID und Größenlimits am Executor nachprüfen. Vorlagenquelle und Identität in der Quittung binden. |
| Status und Readback | Native Task-ID (UPID), Abschluss, erlaubte begrenzte Logdaten und tatsächliche Zielbeobachtung | Task-Herkunft, Ergebnis und Nutzwirkung getrennt halten. Task-API kann Zugriff per Besitzer oder Knotenrecht gewähren. |
| Spätere Mutationen | Action-spezifische Änderung mit von PVE unterstützter Konfliktbedingung | Einen nativen Konfigurations-Digest verwenden, wenn die konkrete Methode ihn prüft. Weitere Methoden und Rechte benötigen eigene Gates. |

Ein Token mit Privilegientrennung wirkt innerhalb der Schnittmenge aus
Rechten des zugehörigen PVE-Benutzers und des Tokens. Für Beobachtung,
Gastaktion und Backup sind getrennte Credentials mit getrenntem Zugriff
vorgesehen. Der Connector kann nur registrierte Routen und Ziel-IDs
auflösen. Die UI erhält weder Tokenwerte noch einen generischen
API-Proxy. Bei Rotation ist Task-Readback mit der neuen Identität
explizit zu prüfen, bevor der alte Credential-Pfad entzogen wird.
Ein bereits angenommener PVE-Task kann nach Tokenentzug weiterlaufen.
[PVE-Token und ACLs](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) ·
[PVE Tasks API](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Tasks.pm)

**Auftragszustände.** `prepared → dispatching → accepted → verifying →
succeeded` ist der reguläre Pfad. Ein eindeutiger Fehler führt nach
Prüfung zu `failed`. Ein API-Timeout nach Dispatch führt zu `uncertain`.
Nur Leseabfragen können automatisch wiederholt werden. Für einen bereits
angenommenen Auftrag dient die UPID als Referenz auf den nativen Ablauf.
Ein eindeutiger Nachweis kann einen unklaren Job auflösen. Fehlende
Taskdaten, abgelaufene Logaufbewahrung oder eine passende Laufzeitänderung
durch einen anderen Operator beweisen allein keinen Abschluss. `uncertain`
hält die Ressourcensperre über Neustarts und Agentwechsel hinweg.
[Schreibfencing und Jobübernahme](07-steward-ha.md)

### Konflikte und Fehlerfälle

| Situation | Geplante Reaktion | Evidenz |
|---|---|---|
| Zwei Aufträge reservieren dieselbe VMID | Lokale Reservierung blockiert konkurrierende Steward-Aufträge. Native Anlage entscheidet über externe Konflikte. | Höchstens ein erzeugter Gast; kollidierender Job trägt den echten PVE-Konflikt. |
| VMID wurde zwischen Vorschau und Apply neu verwendet | Generation oder Identitätsbeleg hat sich geändert. Vorherige Freigabe verfällt. | Alter Plan löst keinen Aufruf aus; neue Zuordnung bleibt sichtbar. |
| Erfolgreicher HTTP-Aufruf mit laufendem Task | Auftrag bleibt in Ausführung. | Native Task-ID, Node und Zeitpunkt in der UI. |
| Task meldet abgeschlossen, Gastzustand weicht ab | Readback meldet Abweichung; Auftrag bleibt ungeklärt oder endet mit geprüftem Fehler. | Task-Abschluss und tatsächlicher Zustand sind beide sichtbar. |
| Zertifikat wurde erneuert | CA-validierte Erneuerung folgt dem registrierten Namen. Pin-Wechsel erfordert vorherigen Nachweis. | Unbekannter Endpoint wird gesperrt; bestätigte Rotation erhält Ressourcenidentitäten. |
| Knoten A nicht erreichbar, B sieht dieselbe PVE-Instanz | Lesepfad kann nach Prüfung auf B wechseln. | Keine zweite PVE-Instanz und kein automatischer Wiederholungs-Schreibaufruf. |

## Umsetzung und Abnahme je Karte

| Karte | Testbare Umsetzung | Freigabe-Beleg |
|---|---|---|
| PX01 | Build/Verifikation, isolierte Units, lesender Preflight und reproduzierbarer Rückbau. | Reales PVE amd64 mit vorhandener Test-VM und Test-LXC, jeweils Upgrade, Reboot und Rückbau. SSH, PVE, Gastnetz und bestehende Datastores bleiben funktionsfähig. |
| PX02 | Versionsadapter, Teilinventar, Frische und Actor-scoped Cache. | Eingeschränkter Auditor und berechtigter Beobachter sehen die jeweils erwarteten Ressourcen. Rechteentzug enthält keine falsch bestätigte Abwesenheit. |
| PX03 | Gebundene Jobs über existierende Executor-Regeln, asynchroner Readback und Konfliktpfade. | Je QEMU und LXC erzeugen und bedienen. Verlorene Antwort, zwischenzeitliche VMID-Nutzung, verbotener Pool und Wiedervorlage beweisen die Grenzen. |

Offen für PX01 bleiben konkrete PVE-Minor-/Patchstände und das endgültige
Paketformat. PX02 verifiziert Task-Lesezugriff mit minimalen Rechten.
PX03 bestimmt den engsten Vorlagenvertrag und die zulässigen Parameter.
Je Karte begrenzt die bestehende *Check/done*-Zeile die Umsetzung.
