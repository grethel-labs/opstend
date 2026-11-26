# 07 · Steward-Quorum, Dienstplatzierung und externe Schreibwirkungen

Karten CP01–CP03 in [Infrastruktur](../infrastructure.md). Stand der
Recherche 2026-11-24. OpsTend benötigt für zentrale Rollen einen
automatischen, überprüfbaren Inhaberwechsel. PVE-Gast-HA, Backup-Replikation
und die Bereitstellung eigener Steward-Dienste bleiben getrennte Abläufe.

## Vergleich der Steuerzustands- und Platzierungsmodelle

| Modell | Vorteil | Betriebskosten und Grenze | Einordnung |
|---|---|---|---|
| SQLite pro Einzelinstanz mit geprüftem Export | Bestehender RC1-Pfad, wenig Betrieb, lokale Transaktionen und Rücksicherung | Eine aktive Steuerinstanz. SQLite-WAL benötigt gemeinsam erreichbaren Speicher für Prozesse auf demselben Host; WAL auf einer Netzwerkfreigabe eignet sich nicht für mehrere Steuerhosts. | Standard bis M14 und weiterhin für kleine Profile. [SQLite WAL](https://www.sqlite.org/wal.html) |
| 3 etcd-Mitglieder mit engem KV-Datenmodell | Konsistente bedingte Transaktionen, Revisionen, Leases und Snapshot-/Restore-Werkzeuge | Dedizierter Betrieb in einem stabilen lokalen Netz. Größenlimit, Watch-Resync, Zertifikate und Compaction erforderlich. | Bevorzugter CP01-Kandidat für wenig autoritativen Zustand. [etcd API](https://etcd.io/docs/v3.6/learning/api/) · [Garantien](https://etcd.io/docs/v3.6/learning/api_guarantees/) |
| rqlite oder eine weitere replizierte SQL-Schicht | SQL-nahe Modellierung mit Konsens unter dem Datenbankdienst | Netzwerk-API, eigene Lesekonsistenz, andere Transaktionsgrenzen und Migrationsaufwand. Bestehende lokale SQLite-Dateien werden nicht zu verteilten Exekutor-Stores. | Spätere Alternative bei belegtem relationalem Bedarf. [rqlite Design](https://rqlite.io/docs/design/) |
| PostgreSQL mit Patroni | Ausgereifte relationale Abfragen und replizierter Datenpfad; verschiedene synchrone Profile | PostgreSQL, failover-fähiger Datenbankzugang und ein unterstützter Distributed Configuration Store. Replikationsmodus bestimmt Verfügbarkeits- und Datenverlustverhalten. | Interessant bei höherem relationalem Datenvolumen, im ersten Quorum-Profil mehr Komponenten als nötig. [Patroni Replication Modes](https://patroni.readthedocs.io/en/latest/replication_modes.html) |
| JetStream-Streams und KV | Geeignet für dauerhafte Nachrichten, Replay und Watch-ähnlichen Zugriff | Stream-, Lesekonsistenz- und CAS-Vertrag muss zum konkreten Invariantensatz passen. Annahme und native Wirkung bleiben separat. | Option für später gemessenen Ereignisbedarf. [NATS Key Value](https://docs.nats.io/learn/key-value/) |
| Kubernetes oder Nomad als Dienst-Orchestrierung | Platzierung, Lebenszyklus und Rollenwahl in einem vorhandenen Mehrnutzer-Orchestrator | Der Betreiber muss diesen Orchestrator betreiben. Eine Lease schützt PVE-Aufrufe und andere externe Wirkungen nur mit zusätzlichem Ausführungsvertrag. | M14 setzt keine dieser Plattformen voraus. Bestehende Cluster kommen als späterer Hosting-Adapter infrage. [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/) · [Nomad Scheduling](https://developer.hashicorp.com/nomad/docs/concepts/scheduling/how-scheduling-works) |

**Vorläufige Wahl.** Ein einzelner SQLite-Writer bis M14. Dann ein
opt-in etcd-3.x-Profil mit drei stimmberechtigten Mitgliedern am
gleichen Standort, auf getrennten physischen Hosts und mit separaten
zuverlässigen Start-/Datenträgerpfaden. Jeder Stimmberechtigte führt
replizierten Zustand. Zwei Hot-Standbys einer Anwendung und zwei
weitere Mitglieder einer Datenbank sind unterschiedliche Rollen. Bei
einer aktiven und nur einer einsatzbereiten Dienstinstanz ist das
dritte etcd-Mitglied weiter Teil des Quorums. NAS und beide vServer
haben in diesem Referenzprofil keine Stimmen.
[etcd Failure Modes](https://etcd.io/docs/v3.6/op-guide/failures/) ·
[etcd Hardware Recommendations](https://etcd.io/docs/v3.6/op-guide/hardware/)

## Datenvertrag und Wiederaufbau der Lesesicht

| Autoritativer KV-Zustand | Außerhalb des KV |
|---|---|
| Flottenkopf und ausgewählte Richtlinienrevisionen, Agentenregister, aktuelle Widerrufe, Versionen, Rollenzustand, Claims, Ressourcensperren, Zeitfenster-Cursor, Hash und Locator archivierter Quittungen | Lokale Executor-Stores, Rohmetriken, Logs, Bulk-Inventar, Backup-Blöcke, Artefakte und geheime Werte |
| Kleine Datensätze mit Schema-Version. Feste Präfixe und Identitäten für jeweils begrenzte Schreibrechte. TTL nur für nachweisbar temporären Zustand. | Projektionen und Historie in passenden lokalen oder unabhängigen Speichern. Lesbare Replikate erhalten eine durch Versionsbelege gebundene Sicht. |

Jede autoritative Schreibmutation verwendet eine Transaktion, die alle
dafür benötigten Vorbedingungen prüft. Default-KV-Reads können
linearisiert sein. Ein absichtlich lokaler oder serieller Read aus
einem beliebigen Member sowie eine Watch allein genügen für die
Ausführungsautorität nicht. Watches aktualisieren Projektionen und
Endpunkt-Routing. Nach Compaction oder Lücke beginnt eine Projektion
an einem konsistenten Snapshot und setzt den Strom ab dem passenden
Revisionspunkt fort. Das Datenmodell bewahrt die letzte berechtigte
Frische. Storage-Quote, Compaction und Backup werden überwacht.
[etcd API Guarantees](https://etcd.io/docs/v3.6/learning/api_guarantees/) ·
[etcd Security Model](https://etcd.io/docs/v3.6/op-guide/security/)

## Rollenwahl und Ressourcen

| Modell für Ersatzdienste | Ressourcen und Startzeit | Wahl |
|---|---|---|
| Kaltreserve | Kein laufender Dienst, Start und Abgleich im Fehlerfall. | Geeignet für seltene oder nicht zeitkritische Verwaltungsrollen. |
| Warme Reserve | Vorbereitete Installation und Datenreferenzen, Startprozess beim Ausfall. | Option bei knappen Ressourcen und gemessen ausreichender Übernahmezeit. |
| Hot-Standby | Vorbereiteter laufender Prozess mit geprüftem Datenstand. Hält Ressourcen bereit und kann die Rolle nach Freigabe übernehmen. | Standard für die ein bis zwei Ersatzinstanzen von zeitkritischen RC2-Rollen. |
| Aktiv-aktiv | Alle fähigen Instanzen nehmen aufgeteilte Arbeit an. Erfordert eindeutige Partitionierung und Claims je Wirkungsbereich. | Für später gemessenen Skalierungsbedarf. Rechte- und Lesezugang können unabhängig von der schreibenden Rolle redundant angeboten werden. |

Jede Rolle hat einen aktiven Slot, gewünschte ein bis zwei Standbys,
erlaubte Host-/Site-Scopes, Ressourcenbedarf, Mindestversion und
Readiness-Anforderungen. Pro Kandidat kennt der Scheduler Identität,
physischen Host, Ausfalldomäne, bestätigten Ledger-Stand und freie
Kapazität. Steuerungs- und Arbeitsrolle werden separat modelliert.
CP03 beginnt mit Flottenkoordination und Backup-Planung.
PVE-, PBS- oder Restic-Datenübertragungen laufen auf ihrem jeweiligen
Ausführungspfad weiter.

1. Entferne Kandidaten mit fehlender Freigabe, altem Datenstand,
   inkompatibler Version, Drain, nicht belegter Ausfalldomäne oder
   ungenügender Restkapazität. Ziehe Reserven anderer Workloads
   ab, einschließlich der späteren KI-Reserve auf dem Beelink.
2. Bevorzuge die bestehende aktive Rolle, solange sie alle Bedingungen
   erfüllt. Sonst sortiere nach expliziter Richtlinienpriorität,
   Ressourcenreserve und einer stabilen Host-ID. Bestätige neue
   Inhaberschaft atomar mit Generation und neuer Epoche. Die stabile
   Regel bei gleich geeigneten Kandidaten macht die automatische
   Auswahl testbar und unabhängig von der Reihenfolge der Abfragen.
3. Platziere die Standbys auf getrennten physischen Hosts und
   möglichst getrennten Fehlerpfaden. Ein vorgewärmter Prozess
   ist erst bereit, wenn unterstützte Version, bestätigte Revision
   und Testzugang zum gesicherten Ausführungspfad passen.
4. Fällt die Redundanz unter das Ziel, zeigt OpsTend Ursache und
   verbleibende Rollen. Ein zurückgekehrter Host beginnt als
   Kandidat. Repriorisierung und Rückwechsel geschehen bei
   geplanter Wartung oder bestätigtem Bedarf. Kurzzeitige
   Metrikschwankung löst keinen dauernden Wechsel aus.

Planungsziel für das Referenzprofil sind 60 Sekunden bis zur erneuten
Lesbarkeit und 120 Sekunden bis zu neuen sicheren Schreibaufträgen
nach Ausfall einer aktiven Rolle. Voraussetzungen sind erreichbares
Quorum, Zugang und Ziel sowie eine freie konfliktfreie Ressource.
Readiness, Keepalive und Lease-Dauer werden mit Host-Pausen und I/O-Last
vermessen. Eine Uhr oder eine veraltete Health-Information begründet
keinen neuen Auftrag.

## Jede Außenwirkung braucht eine dauerhafte Sperre

Eine Steward-Lease kann eine Anwendung koordinieren. Die native
PVE-API erhält kein allgemein gültiges transaktionales Fencing-Token
für diese Lease. Ein in der letzten Millisekunde pausierter Sender
kann später noch einen zuvor autorisierten Request absetzen.
Konsens über einen Job und HTTP-Wirkung liegen auf verschiedenen
Systemen. Die sichere Grenze ist deshalb der quittierte,
übernahmefeste Claim zusammen mit dem einzigen zugelassenen
Ausführungspfad je Ziel.

| Fencing-Variante | Wirkung für den verspäteten Aufruf |
|---|---|
| Nur Lease oder kurze Verzögerung vor Übergabe | Der alte Sender oder sein Request kann länger pausieren. Zeit allein reicht zur sicheren Wiederfreigabe des Wirkungsbereichs nicht aus. |
| Sequenz- oder Epochennummer vom nativen Empfänger geprüft | Der Empfänger kann zu alte Aufrufe zurückweisen. Das ist nur bei einer dokumentierten und getesteten nativen Capability tragfähig. |
| Dauerhafter Dispatch-Claim mit terminaler Evidenz | Wirkt innerhalb des kontrollierten Steward-Pfads, auch wenn ein natives Ziel keine Steward-Epoche versteht. Ein dauerhaft unklarer Dispatch hält den Wirkungsbereich gesperrt. |

Chubby beschreibt dasselbe Grundproblem bei verspäteten Nachrichten.
Seine Sequenzbelege werden vom Empfänger validiert. Für Ziele ohne
solche Unterstützung beschreibt das Paper die Grenzen einer
Sperrverzögerung. PX03 und CP02 prüfen deshalb je Aktion, welche
Empfängersemantik tatsächlich zur Verfügung steht.
[Chubby, OSDI 2006, Abschnitt 2.4](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows.pdf)

| Phase | Zentrale Transaktion oder Zielnachweis | Verhalten bei Failover |
|---|---|---|
| `prepared` | Gebundene Freigabe und aktueller Auftrag, noch kein Auftrag versandt | Neue aktive Rolle prüft erneut und kann die Ausführung übernehmen. |
| `dispatching` | Claim mit Generation, Ressource, Aktion, Writer und wirksamer Zielsperre bestätigt, während seine Epoche gültig ist | Diese nicht an die Rollenlease gebundene Sperre bleibt bestehen. Keine konkurrierende Aktion oder parallele zweite Ausführung. |
| `accepted` / `verifying` | Native Task-ID und Ziel sind bekannt, Readback läuft | Neuer Rolleninhaber verfolgt die vorhandene UPID. Ein abgelaufener Auftrag löst keinen zweiten Schreibaufruf aus. |
| `uncertain` | Antwort fehlt, Abschluss oder Folge des alten Schreibwegs unklar | Halt auf dem Wirkungsbereich. Alte Ausführung nachweislich beenden oder wirksam isolieren und native Tasks/Ziel lesen. Fehlende Belege lassen den Fall gesperrt. |
| Terminal | Passende Evidenz für Abschluss, Ausführungsausschluss oder ausdrücklichen fachlichen Abgleich nach wirksamem Fencing | Sperre in derselben Transaktion lösen, die die terminale Quittung festhält. Ein neuer Auftrag braucht eigene Vorbedingungen. |

**Geltungsbereich der Garantie.** Nach verlorenem Quorum kann OpsTend
keinen neuen Dispatch-Claim bestätigen. Bereits beanspruchte oder
native angenommene Vorgänge können sich weiter auswirken. Ein
fehlgeschlagener Claim führt zu einer Leseprüfung anhand der
Idempotenzkennung und zu keinem Request. HTTP-Retry oder Weiterleitung
für registrierte Schreibaktionen sind deaktiviert. Der Ausführer
speichert den Claim vor dem einzigen Versandversuch pro Auftrag.
Der Executor journalisiert eine unwiederholbare Versandabsicht vor
dem I/O. Nach Prozessneustart, Übergabe oder unbestimmter Transaktion
liest der Executor Claim und Zielstatus zur Klärung. Der Versand wird
dabei nicht aus dem Journal wiederholt. Gateway-/Agentenkennung und
der auditfähige native Ausführungspfad bleiben beim Claim.
Native Außenwirkung lässt sich im Unsicherheitsfall
nicht durch Ablauf der Lease, Schlüsselrotation allein oder ein leeres
Task-Listing ausschließen. Für Rotation und Sperrfreigabe müssen
eventuell vor dem Widerruf angenommene native Tasks berücksichtigt
werden. Dieser Einsatz von Fencing gilt für von OpsTend kontrollierte
Pfadidentitäten. Manuelle PVE-Aktionen werden als externe Änderungen
beobachtet und führen gegebenenfalls zum Abgleich.

**Beispiel mit getrennten NUCs.** A hat einen Shutdown beansprucht und
friert vor dem Aufruf ein. B gewinnt die Rolle, sieht den bestehenden
Claim und blockiert nur den betroffenen Gast und seine relevanten
Sperrbereiche. B kann andere Gäste bedienen. A kehrt zurück. Sein
alter Claim begründet keine zweite Ausführung und kann höchstens
noch den einmal versandfähigen bereits reservierten Vorgang
beeinflussen. B darf den Gast erst neu beauftragen, wenn zuvor
abgesandter oder noch ausstehender alter Versand mit terminaler
Evidenz oder wirksamem Fencing samt nativem Abgleich geklärt ist.

## Verwaltungsendpunkt und vollständiger Verlust

| Zugang | Vorteil | Abnahmegrenze |
|---|---|---|
| Mehrere registrierte Endpunkte | Geeignet für Agenten mit kontrollierter Reihenfolge und TLS-Identität. Kein externer Load Balancer erforderlich. | Greift bei langsamen/unerreichbaren Endpunkten fristgerecht auf einen anderen autorisierten Zugang zu. |
| Vorhandener redundanter privater Proxy oder Load Balancer | Stabile Adresse für Browser, CLI und Agenten. | Proxy-Instanzen haben eigene Ausfalldomänen. Health-Check und Autorität unterscheiden sich. Ein einzelner Proxy bleibt ein Ausfallpunkt. |
| Lokale virtuelle Adresse im geeigneten Netz | Einfacher stabiler Einstieg innerhalb eines qualifizierten LAN-Profils. | L2-/L3-, Switch- und Site-Abhängigkeiten werden geprüft. VRRP ersetzt keine Steward-Ausführungsautorität. [RFC 9568](https://www.rfc-editor.org/rfc/rfc9568.html) |

Der Wiederaufbau nach vollständigem Verlust beginnt außerhalb des
alten Pfads. Restore-Artefakt, Hash, Version, Schlüssel und Anleitung
existieren extern. Ein etcd-Restore bildet einen neuen Cluster aus
dem Snapshot. CP01 prüft Revisionssprünge und erzwungene
Neuinitialisierung von Watch-Lesern. OpsTend legt zusätzlich eine neue
Steuerungs-Generation fest, damit ältere Autorisierungen keine
Gültigkeit durch wiederverwendete Zähler erhalten. Vor der
Schreibfreigabe müssen alte Write-Credentials und Pfade gesperrt und
native Tasks, Zielzustand und eventuell im Snapshot fehlende Jobs
abgeglichen sein. Das tatsächliche RPO entspricht dem verwendeten
externen Snapshot plus dessen Belegumfang.
[etcd Disaster Recovery](https://etcd.io/docs/v3.6/op-guide/recovery/)

## Abnahme

- **CP01:** Mehrheitstests und Revisionsverhalten. Import von einer
  SQLite-Steuerung mit angehaltenem alten Writer und nachgewiesenem
  Zustand. Restore einer eigenen Testgeneration und Ablehnung alter
  Autorisierung. Bestätigte KV-Änderungen überstehen Einzelausfall.
- **CP02:** Unterbrechung vor/nach Claim, direkt vor nativer Aktion und
  nach Annahme ohne Antwort. Konkurrenz mehrerer Scheduler und
  pausierter alter Ausführer, Netzpartition am PVE- und am
  Steuerungspfad. Sperre auf betroffenen Bereichen, Fortschritt
  unabhängiger Ressourcen. Kontrollierter Nachweis nativer Taskzahl.
- **CP03:** Ein und zwei Standbys im realen Referenznetz, Wiederaufnahme
  am Verwaltungsendpunkt, Readiness, laufende Jobs, Platzierungsreserve,
  geplantes Drain und kompatible Versionsfenster. Die lokale Server-
  und Storage-Position jedes Stimmberechtigten wird belegt.
- **IR01:** Physischer Ausfall, WAN-Verlust, NAS-Verlust, danach
  unabhängiger Steuerzustandsrestore. Der Fencing-Beleg bleibt
  unabhängig von [PVE-HA](04-proxmox-ha-and-storage.md) bewertbar.
