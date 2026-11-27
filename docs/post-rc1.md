# Nach RC1: OpsTend als Infrastrukturverwaltung

**Status:** geplant, 2026-11-24. Start nach dem RC1-Abschluss gemäß
[goal.md](goal.md). Dieser Plan führt den Fahrplan mit M9–M15 bis RC2 fort.
Er setzt auf dem in RC1 tatsächlich freigegebenen Funktionsumfang auf.
Eine in RC1 zurückgestellte Funktion ist nur dann Voraussetzung, wenn ihre
Karte unten ausdrücklich genannt wird.

## Ziel und Reihenfolge

Ein Operator installiert OpsTend nativ auf einem einzelnen Proxmox-VE-Host,
bindet weitere Installationen zu einer gemeinsamen Flotte zusammen und verwaltet
Proxmox-Cluster, eigenständige Hosts, Linux-Server und ausgewählte Geräte in
einer Oberfläche. Gemeinsame Richtlinien, Backup-Ziele und eine Quellenangabe
für jede Beobachtung machen sichtbar, was wo läuft und wer dafür zuständig ist.
Auf jedem angebundenen Rechner kann ein schlanker Agent laufen. Die zentralen
Steward-Dienste werden nach Bedarf auf geeigneten Rechnern platziert.

| Meilenstein | Karten und Arbeitspakete | Abschlusskriterien | Stand |
|---|---|---|---|
| M9 · Proxmox nativ | [PX01–PX03](plans/proxmox.md#px01--native-installation-und-preflight) | Signierte native Einzelhost-Installation mit lokaler Bedienung, Inventar, freigegebenem VM-/LXC-Lebenszyklus und Anlagen aus zugelassenen Vorlagen. Upgrade, Neustart und Rückbau auf echtem PVE geprüft. | Teilabnahme 2026-11-27. LXC-Klonprüfung und S01-Freigabe offen. [Nachweise](STATUS.md#card-state) |
| M10 · Gemeinsame Flotte | [FL01–FL03](plans/fleet.md#fl01--registrierung-und-identität) | Einzelhosts und bereits bestehende PVE-Cluster rechnen unter einer gemeinsamen Verwaltung mit stabilen IDs, einer Richtlinienhistorie und pro Ziel sichtbarer Übernahme. Eine zentrale Instanz genügt. | FL01.1 implementiert. Enrollment, Übernahme und Flottenabnahme offen. |
| M11 · Externe Backups | [BK09–BK11](plans/fleet.md#bk09--gemeinsame-backup-richtlinien-und-zielkatalog) | Gemeinsamer Zeitplan, Quoten und Katalog für PVE/PBS und Linux/Restic. Zwei echte Wiederherstellungen aus einem unabhängigen Standort mit Nutzdatenprüfung. | geplant |
| M12 · Proxmox HA | [PH01–PH03](plans/proxmox.md#ph01--ha-inventar-und-eignungsprüfung) | Bestehendes HA-Cluster mit drei Knoten integriert. Anwendbarkeit, geplante Wartung und echter Fencing-/Quorum-Test für je einen ausgewählten VM- und LXC-Gast belegt. | geplant |
| M13 · Server, Geräte und Dashboard | [IN01–IN03](plans/infrastructure.md#in01--eigenständige-linux-server) | Lokale und externe Linux-Ziele sowie ausdrücklich eingebundene Geräte erscheinen mit Inventar, Topologie, Messwerten, Backup- und Ereignisansichten in einer Oberfläche. Rollen gelten auch für Beziehungen. | geplant |
| M14 · Hochverfügbares OpsTend | [CP01–CP03](plans/infrastructure.md#cp01--replizierter-steuerzustand-und-wiederanlauf) | Eine aktive Instanz je freigegebener Rolle, ein bis zwei betriebsbereite Ersatzinstanzen nach Richtlinie, automatischer Rollenwechsel innerhalb eines Standorts mit 2-von-3-Quorum und geprüfter Schreibsperre für alte Instanzen. | geplant |
| M15 · RC2 | [IR01–IR02](plans/infrastructure.md#ir01--integrierte-abnahme-der-referenzflotte) | Integrierte Abnahme einer gemischten Flotte mit acht PVE-Hosts, NAS und externen Linux-Servern, unabhängige Wiederherstellung, Upgrade aus RC1 und signierte Veröffentlichung mit nachvollziehbarer Support-Matrix. | geplant |

M9–M15 werden in dieser Reihenfolge begonnen. Unabhängige Zeit- und Host-Gates
laufen nach Regel 8 in [goal.md](goal.md) parallel. Jede Karte behält ihre
eigenen Voraussetzungen für Freigabe und echte Abnahme. M10 kann lokale
Steward-Backups inventarisieren; eine zentrale Restic-Ausführung in M11
verlangt die hierfür freigegebene B08-Kette. Zentrale Sicherheitskorrekturen
oder Funktionen aus X1 bleiben in ihrem eigenen Arbeitsstrang.

## Referenzaufbau mit lokalen und externen Systemen

Das Beispiel umfasst **acht PVE-Hosts, ein lokales NAS und zwei externe
Linux-Server**. Die Zeilen beschreiben die vorhandene Hardware und
vorgeschlagene Rollen. Andere Installationen setzen dieselben Funktionen aus
konfigurierbaren Standorten, Ressourcen, Fähigkeiten und Rollen zusammen.

| System | Anschluss und geplante Rolle |
|---|---|
| **3 Intel NUCs mit Proxmox VE** | Drei Mitglieder eines PVE-HA-Clusters. OpsTend führt das Cluster als eine PVE-Instanz und zeigt die einzelnen Knoten sowie HA-Eignung und tatsächliche Platzierung je Gast. |
| **4 weitere Intel NUCs mit Proxmox VE** | Vier eigenständige PVE-Instanzen mit gemeinsamem Inventar und Richtlinien. Geeignete NUCs können Steward-Steuerung oder einen lokalen Backup-Dienst beherbergen. |
| **Beelink GTR9 Pro mit Proxmox VE** | Fünfte eigenständige PVE-Instanz mit höher eingestelltem RAM. OpsTend zeigt seine VMs und LXC. Für einen späteren KI-Container wird eine ausdrückliche Hostzuordnung mit RAM-Reserve vorgesehen. Die Dienstplatzierung berücksichtigt diese Reserve. |
| **Raspberry Pi mit 2 × 2 TB NVMe-SSDs** | Vorläufiges lokales NAS. Die Oberfläche zeigt den NAS-Dienst, die zugeordneten Freigaben und lesend gemeldete Erreichbarkeit und Kapazität. Nutzbare Kapazität und Plattenredundanz folgen dem tatsächlich gewählten Layout. |
| **2 externe vServer mit Ubuntu 26.04 LTS** | Je 8 GB RAM und 4 vCPU. Anbindung als eigenständige Linux-Hosts über ausgehende Agentenverbindungen. Mögliche Rollen sind externe Erreichbarkeitsbeobachtung auf einem Host und ein verschlüsseltes Restic-Ziel auf dem anderen, sofern Speicher und Durchsatz passen. |

Für Steward-HA sind drei lokal getrennt startfähige Management-Instanzen
vorgesehen, beispielsweise auf je einem der NUCs 1, 4 und 5. Die drei
Stimmberechtigten brauchen getrennte Host- und Boot-Pfade. Die vServer
werden im Referenzprofil außerhalb des Steward- und des PVE-Quorums geführt.
Bei WAN-Ausfall können beide lokalen Quoren weiterarbeiten, solange ihre
lokalen Voraussetzungen erfüllt sind. Provider, Region und Netzpfad
beschreiben die Ausfalldomäne der vServer.

Ein einzelner PVE-Host mit lokaler Steuerung bildet das kleinste Profil.
Mehrere eigenständige PVE-Hosts, mehrere Cluster oder reine Linux-/Geräteziele
können schrittweise hinzukommen. Im Datenmodell sind Anzahl,
Hersteller, CPU-Architektur und Standort Eigenschaften des Inventars.
Freigaben beruhen auf unterstützten Fähigkeiten und konkreten Adapter-,
Netz- und Ressourcenprüfungen. Bei Bedarf kann beispielsweise ein
Sieben-NUC-PVE-Cluster als eine Instanz angebunden werden. Mit den
Standardstimmen braucht dieses Cluster vier Stimmen, auch wenn ausgewählte
Gäste nur auf drei Knoten platziert werden.

Vor M12 werden CPU-Generationen, freier und reservierter RAM, SSDs,
Netzwerkkarten, Bridges/VLANs, Stromversorgung, Switches und Passthrough
dokumentiert. PVE-Cluster-Mitgliedschaft und der Umzug vorhandener Gäste
bleiben vorbereitete Betreiberaufgaben. Corosync nutzt den lokalen Netzpfad;
WAN-Ziele werden über das Steward-Managementnetz angebunden. Gemeinsamer
Strom, Switch oder Storage werden im Dashboard als Ausfalldomänen sichtbar.
[Proxmox-Clusterverwaltung](https://github.com/proxmox/pve-docs/blob/master/pvecm.adoc)

```mermaid
flowchart TB
    User["Operator · Web und CLI"] --> Entry["Steward-Verwaltungsendpunkt"]
    Entry --> Active["Aktive Steward-Steuerung"]
    Active <--> State["Steuerzustand · drei Quorum-Mitglieder"]
    Standby["Ein bis zwei betriebsbereite Ersatzinstanzen"] <--> State
    Active --> Edge["Zielgebundene Agenten und Adapter"]
    Edge --> PVE["Proxmox HA · NUC 1–3"]
    Edge --> Solo["4 eigenständige Proxmox-NUCs"]
    Edge --> Beelink["Eigenständiger PVE-Host · Beelink GTR9 Pro"]
    Edge --> NAS["Raspberry Pi · lokales NAS"]
    Edge --> Remote["2 externe vServer · Ubuntu 26.04 LTS"]
    Beelink -. Hostzuordnung und RAM-Reserve .-> AI["Späterer KI-Container"]
    PVE --> PBS["Qualifiziertes PBS-Ziel · Gast-Backups"]
    Solo --> PBS
    Beelink --> PBS
    PBS --> OffsitePBS["Unabhängiges PBS-Ziel · externe Kopie"]
    Remote --> Restic["Restic über HTTPS · nach Kapazitätsfreigabe"]
```

## Zuständigkeiten und Betriebsprofile

| Ebene | Führende Instanz | Verhalten bei Ausfall |
|---|---|---|
| VM, LXC, Bridge, Datastore, PVE-Task und Gastplatzierung | PVE-API und bei HA der PVE-HA-Manager. OpsTend zeigt deren tatsächlichen Zustand, prüft Vorbedingungen und beauftragt zugelassene Aktionen. | PVE führt Gast-Failover und Fencing selbst durch. OpsTend blockiert koordinierte Schreibaktionen bei fehlender Autorität oder unklarem Zustand. |
| Lokale Linux-Anwendungen | Der registrierte Steward-Executor des Hosts führt freigegebene RC1-Aktionen aus und protokolliert sie lokal. | Laufende Workloads und hostlokal verantwortete RC1-Funktionen arbeiten nach ihrer bestehenden Policy weiter. Flottenverwaltete Jobs brauchen eine gültige Freigabe des zuständigen Koordinators. |
| Flottenrichtlinien, Freigaben und Rollen | Ab M10 eine führende Koordination; ab M14 optional ein replizierter Steuerzustand mit Quorum. Jede verfügbare UI-Instanz wendet die Rollen der Flotte an. | Eine Quorum-Mehrheit kann die Steward-Rolle neu vergeben. Die Minderheit kann datierte Informationen für bereits bestehende Sitzungen innerhalb einer begrenzten, zuvor bestätigten Lesefreigabe zeigen. Neue Sitzungen und Schreibzugriffe brauchen eine erreichbare Autorität. |
| Backup-Daten und Gerätebeobachtung | PBS oder Restic halten die Daten. Geräte liefern Beobachtungen über Einzeladapter oder einen Agenten im Zielnetz. | Backends und nativ verantwortete Zeitpläne laufen eigenständig. Die UI zeigt Zeitstempel und Erreichbarkeit. Ein Ausfall löst keine erfolgreiche Backup- oder Gesundheitsmeldung aus. |

Das Profil **Einzelhost** installiert den Agenten, optional die lokale
Steuerung und ihre SQLite-Datenbank direkt auf PVE mit eigenen systemd-Identitäten.
Das Profil **Agent** verbindet einen Host mit einer Flotte und lässt schwere
Dienste wie Scanner, Builder oder KI standardmäßig deaktiviert. Im Profil
**entfernter Anschluss** ruft ein registrierter Connector die PVE-API auf, wenn
auf einem Host keine Steward-Software installiert werden soll. Im Profil
**Steuerung** laufen API, Scheduler und Speicher auf ausgewählten Management-
Instanzen, beispielsweise in getrennt platzierten VMs oder auf separatem Linux.
M9–M13 nutzen für die Flotte eine einzelne Steuerung. In M14 kommt das optionale
Quorum-Profil hinzu. Die lokale SQLite- und Executor-Architektur aus
[ADR 0001](adr/0001-architecture.md) bleibt die Basis des Einzelhostbetriebs.
Der verteilte Steuerzustand wird in CP01 als eigenständiges Betriebsprofil in
einem ADR festgelegt.

## Gemeinsame Einstellungen und Befehle

- **Identitäten.** Eine Flotte vergibt stabile Site-, PVE-Instanz- und Host-IDs.
  Ein Gast hat die Identität `(PVE-Instanz-ID, Gasttyp, VMID, Generation)`.
  Der aktuelle PVE-Knoten ist eine Eigenschaft des Gasts. Eine nachweislich neu
  belegte VMID bekommt eine neue Generation. Bei unklarer Kontinuität muss der
  Operator bestätigen, bevor Rechte oder Richtlinien wieder verbunden werden.
  Name, IP und VMID allein liefern keinen Identitätsnachweis.
- **Vererbung.** Grundeinstellungen der Flotte liefern Vorgaben. Die
  Site-/Gruppenregel und danach die explizite Zielausnahme liefern zulässige
  Abweichungen. Pro Eigenschaft gilt höchstens eine Gruppenzuweisung auf
  derselben Ebene; widersprüchliche Treffer blockieren die Aktivierung.
  Flottenweite Berechtigungsgrenzen und der lokale Sicherheitsrahmen bilden
  gemeinsam die Obergrenze. Die Oberfläche erklärt Herkunft und wirksamen Wert.
- **Änderungen.** CLI und UI arbeiten gegen einen bekannten Revisionskopf.
  Plan, Zielmenge, Revision, Freigabe und Verfallszeit werden gebunden. Hosts
  melden ihre individuell zuletzt angewandte Revision. Offline-Ziele bleiben
  als ausstehend sichtbar und werden beim Wiederverbinden neu geprüft. Der
  Vollzug bleibt je Ziel nachvollziehbar, auch wenn ein Sammelauftrag teilweise
  erfolgreich war. Pro Zeitplan und Ressource wird genau ein Verantwortlicher
  festgelegt. Ein Wechsel zwischen lokaler und zentraler Verantwortung ist
  explizit und wartet laufende Arbeit ab.
- **Zugriff.** Zeitlich beschränktes Enrollment, bestätigte Identität und
  rotierbare Agentenzertifikate. Entfernte Agenten verbinden sich ausgehend über
  mTLS; Zielverbindungen, DNS und TLS-Identität bleiben fest an die Registrierung
  gebunden. Der jeweilige Ausführungspfad hält nur die für registrierte Ziel-IDs
  nötigen Credentials. Die UI, der Scheduler und der Beobachtungsagent
  erhalten keine Schreib-Tokens. Operator, Rolle, Ziel, Revision und native
  Task-ID sind in den freigegebenen Auditansichten korrelierbar.

## Backup, HA und Dienstplatzierung

Eine externe Backup-**Richtlinie** legt Zeitfenster, Ziel, Aufbewahrung,
Verschlüsselung und Wiederherstellungsziel pro Schutzklasse fest. PVE-Gäste
laufen über native Sicherungen zu PBS; die bestehende, freigegebene
Restic-Kette behandelt Linux- und Anwendungsdaten. Ein Standort außerhalb
des PVE- und Steward-Verbands hostet die unabhängige Kopie. Unterschiedliche
Geräte-/Datenklassen dürfen unterschiedliche Backends verwenden und erscheinen
im selben Katalog. Ein Gast mit separat gesicherter Anwendung weist beide
Schutzebenen aus. Der Katalog zeigt Sicherung, Kopie, Integritätsprüfung und
tatsächlichen Daten-Restore jeweils mit eigenem Datum. Für PBS ist ein
Offsite-Pull mit lesendem Quellzugang und eigener Aufbewahrung vorgesehen;
die Weitergabe von Löschungen ist deaktiviert. Schlüssel und Recovery-Daten
werden gesondert wiederherstellbar hinterlegt.
[PBS Remotes und Sync](https://pbs.proxmox.com/docs/managing-remotes.html)

Das Pi-NAS ist im Beispiel lokaler Datei- und Freigabespeicher. Es kann
freigegebene Backup-Exporte aufnehmen und wird mit dem tatsächlich eingesetzten
Protokoll als Speicherquelle angezeigt. Für native PBS-Sicherungen ist eine
unterstützte x86-64-PBS-Instanz mit geprüftem Datastore vorgesehen. Die
externe Kopie nutzt ein erreichbares Ziel in einer anderen Ausfalldomäne.
Auf einem geeigneten Ubuntu-vServer lässt sich der vorhandene
Restic-HTTPS-Pfad nutzen, sofern Platz, Aufbewahrung und Durchsatz geprüft
sind. Das externe PBS-Ziel wird separat qualifiziert. Solange für eine
Schutzklasse kein externes Ziel nachgewiesen ist, zeigt der Katalog die
Deckungslücke. Bei einem Ausfall des Pi-NAS zeigt das Dashboard die
betroffenen Freigaben und Backup-Wege. Das Referenzprofil hält PVE-HA-
Gastdisks und Steward-Quorum-Datenträger auf separat geprüften Speichern.
[PBS-Systemanforderungen](https://pbs.proxmox.com/docs/installation.html#system-requirements) ·
[Steward-Backup-Grundlage](backup-foundation.md)

Beim Proxmox-HA-Pfad prüft OpsTend Quorum, Storage-Zugriff oder qualifizierte
Replikation, Netzkompatibilität und die Platzierbarkeit der Gäste. Für einen
Gast mit lokalem Passthrough oder gebundenem Storage kann der Prüfbericht
bestimmte Ziele ausschließen. Asynchrone Storage-Replikation wird mit dem
möglichen Datenverlust seit der letzten Replikation angezeigt. Der native
HA-Manager entscheidet über Fencing und Wiederanlauf. Aus der PVE-Beobachtung
leitet OpsTend ausdrücklich ab, ob ein Gast noch migriert, bereits auf einem
anderen Knoten läuft oder der Zustand ungeklärt ist.
[Proxmox HA Manager](https://github.com/proxmox/pve-docs/blob/master/ha-manager.adoc) ·
[Proxmox Storage Replication](https://github.com/proxmox/pve-docs/blob/master/pvesr.adoc)

Im Steward-HA-Profil stimmen drei fest aufgenommene Mitglieder über den
Steuerzustand ab. Die Dienstspezifikation je Rolle enthält Anzahl aktiver
Instanzen (zunächst eine), ein bis zwei gewünschte Hot-Standbys,
Mindestkapazität, Version, Datenstand, erlaubte Standorte und
Ausfalldomänen. Der Scheduler schließt unpassende Kandidaten aus, sortiert
nach Richtlinienpriorität, freien Ressourcen und stabiler Host-ID und lässt
die Zuweisung atomar bestätigen. Das ergibt eine automatische, nachvollziehbare
Auswahl. Eine gesunde aktive Instanz bleibt bei Rückkehr eines bevorzugten
Kandidaten aktiv; neue Platzierung folgt Ausfall, Wartung oder einer
bestätigten Anforderung. Standbys sind vorgewärmt und folgen dem bestätigten
Steuerzustand. Ihre Eignung für eine Übernahme hängt unter anderem von einem
nachgewiesenen Datenstand ab. Ein Hot-Standby und ein stimmberechtigtes Mitglied
sind unterschiedliche Rollen. Zwei Dienstinstanzen allein bilden das Profil
mit automatischer Übernahme nur zusammen mit einem dritten erreichbaren
Quorum-Mitglied.
[etcd-Fehlerverhalten](https://etcd.io/docs/v3.6/op-guide/failures/) ·
[etcd API für Transaktionen und Leases](https://etcd.io/docs/v3.6/learning/api/)

Für M14 ist ein einzelner Standort mit getrennten Hosts vorgesehen.
Unabhängige externe Geräte, Agents und Backup-Ziele können bereits vorher
angebunden werden. Ein Standortausfall wird mit Wiederherstellung aus der
externen Kopie bearbeitet. Das Aufnehmen eines zusätzlichen Stimmberechtigten
sowie eine Verlagerung des Quorums bleiben geplante Betreiberaktionen.
Ein bestätigter Befehlsanspruch und sein Status bleiben beim Rollenwechsel
erhalten. Ein ungewisser nativer Task blockiert weitere kollidierende Aktionen
bis zur Abstimmung mit dem ursprünglichen Ziel. Die konkrete Absicherung
gegen verspätete Anfragen steht in [CP02](plans/infrastructure.md#cp02--rollenwahl-schreibsperren-und-job-übernahme).

## Sicht in der Weboberfläche

| Ansicht | Inhalt und Bedienung |
|---|---|
| Flottenübersicht | Status je Standort und PVE-Instanz, Hosts/VMs/LXC, CPU/RAM/Storage mit Zeitfenster, letzte Agentenmeldungen, Quorum je Ebene und jüngste Aufträge. Filter nach Standort, Typ, Gruppe und Status. |
| Infrastrukturkarte | Baum und Graph für `Standort → Cluster/Host → Gast → Dienst` mit separat einblendbaren Kanten für Netz/VLAN, Storage, Backup, Anwendungsabhängigkeit und HA-Platzierung. Klick öffnet Details, Herkunft und Zeitstempel. |
| Ressourcendetail | Ist- und Soll-Zustand, beobachtete Platzierung, Ereigniszeitlinie, Messkurven, Backup-Kopien und Aktionen nach Rolle, Capability und Frische. |
| Backup und Wiederanlauf | Zeitplan, Fehlversuche, letzter externer Prüfstand, geplanter Restore, RPO/RTO je Schutzklasse und letzte tatsächlich gemessene Werte. |
| Steward-Dienste | Aktive Instanz, einsatzbereite Ersatzinstanzen, Datenstand, ausgeschlossene Kandidaten mit Grund, Rollenwechsel und Replikationsstatus. |

Beispiel für den Referenzaufbau: Ein Klick auf eine HA-VM zeigt ihren
aktuellen NUC, mögliche Zielknoten, ihre Bridge, den Datastore und den
letzten geprüften externen PBS-Snapshot. Der darin betriebene Dienst
erscheint als eigener Knoten, wenn ein registrierter Agent oder eine
deklarierte Zuordnung ihn mit der VM verbindet. Sein separat gesicherter
Datenbestand zeigt auf das entsprechende Restic-Repository. Fällt ein NUC
aus, aktualisiert die Ansicht die Gastplatzierung aus PVE und führt den
Steward-Rollenwechsel, falls einer nötig ist, als eigenes Ereignis.

Eine Kante ist als **vom Adapter beobachtet**, **durch den Betreiber
deklariert** oder **abgeleitet mit Beleg** gekennzeichnet. Eine gemeinsame
Bridge belegt Netzanbindung. Schreibfreigaben, Backup-Erfolg und konkrete
Verbindungsnachweise brauchen jeweils eigene Evidenz. Offline und veraltet
verwenden eigene Zustände. Graph und Listenansicht filtern dieselben
berechtigten Objekte vor der Aggregation, einschließlich Kanten und Zählwerten.
Die wichtigste Überschneidung mit Proxmox Datacenter Manager liegt bei
PVE/PBS-Inventar und Gastaktionen. OpsTend bindet PVE und PBS über ihre
nativen APIs ein und verbindet diese Ansichten mit Linux, Geräten,
Richtlinien und Wiederherstellungsnachweisen.
[Proxmox Datacenter Manager](https://pdm.proxmox.com/docs/introduction.html)

## Budgets, Abnahme und offene Entscheidungen

- Ab M9 gelten Regeln 1–10 aus [goal.md](goal.md), die Stop-Regeln und der
  Lead-/Worker-Ablauf pro Implementierungsschritt. Zwei bis drei Schritte je
  Karte sind unten festgelegt. Eine Korrektur von Datenverlust oder
  Privilegienausweitung folgt Regel 2. Zusätzliche Adapter und Funktionen gehen
  mit Kartenzuordnung nach [backlog.md](backlog.md).
- Pro Meilenstein eine zusammengefasste Abnahme auf dem geprüften Commit. Maximal
  zwei Versuche pro Gate. Für M9 wird ein eigener freigegebener PVE-Testhost
  gebraucht. Verschachteltes PVE kann API-/Installationstests abdecken. Für M12
  und M14 werden physische Ausfälle, Quorum und die Wiederanlaufpfade in einer
  dafür freigegebenen Topologie geprüft. Die separate Test-VM für Aufbewahrung und die bestehenden
  RC1-Test-VMs haben ihre in [goal.md](goal.md) definierten Rollen.
  Referenzgeräte, Netzpfade und externe Ziele werden für echte Tests
  einzeln freigegeben.
- Vorgeschlagene Abnahmeziele für das Referenzprofil: Inventar im Normalbetrieb
  innerhalb von 120 Sekunden aktualisiert. Nach Verlust einer aktiven
  Steward-Instanz innerhalb von 60 Sekunden wieder lesbar und innerhalb von
  120 Sekunden wieder schreibbereit, sofern Quorum, Verwaltungsendpunkt und
  Ziel erreichbar sind. RPO 0 für per Quorum **bestätigte** Steueränderungen
  bei diesem Einzelausfall. Für das externe Gast-/Anwendungsbackup gilt im
  Referenztest ein anfängliches RPO-Ziel von 24 Stunden; die Zeit des Restores
  wird pro Datengröße, Backend und Link gemessen. Das RPO bei Quorum-
  Totalausfall ergibt sich aus dem letzten verifizierten externen Snapshot.
  Gast-HA-Zeiten werden separat gemessen. Alle Zeiten sind Zielwerte für die
  Abnahme und werden erst nach der Messung zugesichert.
- PX01 legt die getestete PVE-Version, Hardware-/OS-Profile und das
  Paketformat fest. BK09 fixiert externen Standort, Verantwortliche,
  Schlüsselhinterlegung und Schutzklassen. PH01 legt Storage-Profil,
  CPU-/Netzkompatibilität und besonders gebundene Gäste fest. CP01 legt die
  tatsächlichen Quorum-/Endpoint-Hosts nach Ausfalldomänen fest. Diese
  Entscheidungen werden in den jeweiligen Karten belegt.
- RC2 deckt den kleinsten vollständig geprüften Umfang ab. Weitere
  Storage- und Geräteprofile, clusterübergreifende Live-Migration,
  automatisches Standort-Failover, automatisches PVE-Cluster-Bootstrap
  und automatische Aufnahme von Quorum-Mitgliedern sind Kandidaten für
  spätere Arbeit. RC2 dokumentiert pro Capability die angenommene Topologie
  und den tatsächlich geprüften Support.

### Karten im Detail

- [Proxmox nativ und Proxmox HA](plans/proxmox.md)
- [Flottenverwaltung und externe Backups](plans/fleet.md)
- [Server, Geräte, OpsTend HA und RC2](plans/infrastructure.md)

Der [Recherche- und Architekturindex](plans/infrastructure-design/README.md)
führt pro Themengebiet Varianten, Primärquellen, Entscheidungspunkte und
Bezüge zur Abnahme zusammen. Die [optionalen Ausbaustufen nach RC2](plans/infrastructure-design/10-follow-up-iterations.md)
enthalten eigene Voraussetzungen und Abnahmekriterien.
