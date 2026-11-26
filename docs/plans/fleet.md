# Karten für Flotte und externe Backups

Reihenfolge, Budgets und Referenzaufbau stehen im
[Plan nach RC1](../post-rc1.md). Für Richtlinien und Backups werden die
RC1-Verträge wiederverwendet, soweit das jeweilige Feature freigegeben ist.
[Backup-Grundlage](../backup-foundation.md) · [Karten B01–B08](backups.md)

[Flottenmodell und Vertrauen](infrastructure-design/02-fleet-and-trust.md) ·
[Sicherungs- und Wiederherstellungsvarianten](infrastructure-design/03-backup-and-recovery.md)

## FL01 — Registrierung und Identität

**Voraussetzung:** PX02, PX03 für schreibende Fähigkeiten.
**Einstieg:** Konfigurationsschema, Netzwerk-/Credential-Muster der
RC1-Adapter, native PVE-Inventarisierung.

1. Führe Site-, Host-, PVE-Instanz- und Agentenidentitäten ein. Ein
   PVE-Cluster wird einmal als Instanz registriert und kann mehrere API-Pfade
   mit bestätigter Identität haben. Ein Standalone-Host bildet eine eigene
   PVE-Instanz. Ein Gastwechsel zwischen Knoten erhält die Gast-ID;
   nach Neuverwendung einer VMID wird die Generation fortgeschrieben.
2. Implementiere ein zeitlich begrenztes Enrollment mit explizit bestätigtem
   Ziel, Schlüssel und Capability-Umfang. Unterstütze ausgehende Agenten-
   Verbindungen mit mTLS und API-only-Anschluss über einen Connector im
   Zielnetz. Widerruf und Rotation entziehen alten Credentials den Zugriff.
   Das Zielregister schützt gegen Zertifikats-, DNS- und Instanzwechsel.
3. Übernimm einen bestehenden Einzelhost zunächst lesend. Zeige Konfiguration,
   Rollen und bereits lokale Zeitpläne. Für die spätere Übernahme von
   Richtlinien und Schreibrechten ist der in FL03 beschriebene Prozess
   erforderlich. Entfernen des Anschlusses bewahrt Auftrags- und
   Backup-Referenzen als historische Daten.

**Check/done**: Echte Registrierung von zwei PVE-Instanzen mit gleicher
VMID, Abruf einer PVE-Instanz über mehrere bestätigte Knoten,
Neuverwendung einer VMID, Replay und abgelaufene Einladung, Rotation,
Widerruf und Wiederanschluss ohne doppeltes Inventar.

## FL02 — Gemeinsame Richtlinien und widerrufbare Revisionen

**Voraussetzung:** FL01. **Einstieg:** typisiertes RC1-Konfigurationsschema,
kanonische Revisionen und Kopfvergleich aus L10.

1. Definiere einen revisionsgebundenen Flottenkopf für Ziele, Gruppen,
   lokale Ausnahmen, Wartungsfenster, Rollenzuordnung und Referenzen auf
   Credentials und Backup-Profile. Zeige effektive Werte mit Herkunft.
   Widersprüchliche Gruppenvorgaben und unzulässige Aufweichung des
   lokalen Sicherheitsrahmens halten den Zielplan ausstehend.
2. Stelle für CLI und UI dieselbe Vorschau, Zielmenge, freizugebende
   Revision und Ergebnisansicht bereit. Das einzelne Ziel prüft
   Freigabe und aktuell angewandte Revision, bevor es übernimmt.
   Ein Rollback der Richtlinie ist eine neue Revision auf Basis
   eines früheren Stands. Bereits abgeschlossene externe Aktionen
   behalten ihre eigene Wirkung und ihren Audit-Eintrag.
3. Gib Szenarien für lokale Änderungen, Offline-Ziele, Teilanwendungen und
   spätere Konvergenz an. Ein Offline-Ziel meldet seinen angewandten Stand
   beim Wiederverbinden und übernimmt ausschließlich einen dann gültigen
   Plan. Lokale Abweichungen werden als Konflikt mit Eigentümer sichtbar.

**Check/done**: Zwei konkurrierende Änderungen führen zu einem sichtbaren
Kopfkonflikt. Ein Offline-Ziel bleibt ausstehend und wendet keine
inzwischen widerrufene Revision an. Lese- und Schreibrechte greifen je
Site, Gruppe und Ressource. Revisions- und Exportdaten enthalten
Secret-Referenzen.

## FL03 — Koordinierte Befehle und Eigentumsübergabe

**Voraussetzung:** FL02, PX03. **Einstieg:** RC1-Jobs, Ziel-Locks,
Executor-Freigaben und Auditereignisse.

1. Verwende zunächst genau einen führenden Flottenkoordinator. Implementiere
   den persistenten Befehlspfad von UI/CLI über bestätigten Plan und
   Scheduler zum gebundenen Ziel-Executor. Pro Befehl gelten feste Person/
   Rolle, Zielgeneration, Aktion, Parameter, Richtlinie, Ablauf und eindeutige
   Auftrags-ID. Der Executor prüft erneut seinen lokalen Rahmen, kill switch,
   Ressourcensperre und die Frische der Vorbedingungen.
2. Koordiniere einen expliziten Eigentumsübergang je Ressource und Zeitplan.
   Pausiere alte Auslöser, warte aktive oder ungeklärte Arbeiten ab, bestätige
   den Wechsel lokal und übernimm danach die neue Policy. Unterstütze den
   Rückweg in den Einzelhostbetrieb mit demselben Verfahren. Bei Trennung
   der Verbindung bleibt die zuletzt bestätigte Verantwortung wirksam.
3. Führe Einzel- und Sammelaufträge mit Ergebnis pro Ziel, begrenzter
   Parallelität und deduplizierter Auftrags-ID aus. Nach Wiederverbindung
   werden abgelaufene Freigaben verworfen. Ein unklarer nativer Task bleibt
   über Koordinator-Neustarts hinweg geschützt. Per Hand im PVE-UI
   ausgelöste Arbeit erscheint als externe Änderung; aktuelle Task- und
   Zustandsprüfung gehen Steward-Schreibaufrufen voraus.

**Check/done**: Gemeinsame UI steuert autorisierte Gastaktionen auf
zwei eigenständigen PVE-Instanzen oder einer Instanz und einem weiteren
Host. Der Ausfall eines Ziels lässt andere zu, Offline-Replay nach Ablauf
wird abgewiesen und exakt ein Zeitplan bleibt aktiv. Der Übergang zurück
zum Einzelhost benötigt bestätigte Beendigung zentraler Verantwortlichkeit.

## BK09 — Gemeinsame Backup-Richtlinien und Zielkatalog

**Voraussetzung:** FL03; freigegebene B08-Kette für den verwalteten
Linux-/Restic-Pfad. **Einstieg:** bestehende Backup-Schemata,
`adapters/backups.py`, `backupworker.py` und PX02-Storage-Inventar.

1. Definiere Schutzklassen für Gast, Anwendungsdaten und späteren
   Steward-Steuerzustand. Eine Richtlinie bindet Datenumfang, Zeitplan,
   zulässige Pause, RPO/RTO, Backup-Ziel, Offsite-Ziel, Aufbewahrung und
   Verschlüsselungs-/Schlüsselreferenz. Die Vorschau zeigt Gast- und
   Anwendungsbackup getrennt. Drücke ausgeschlossene Volumes,
   LXC-Bind-Mounts und Passthrough explizit als Deckungslücken aus.
2. Registriere lokale und externe PBS-/Restic-Ziele mit Berechtigungsdomänen,
   Kapazität, unabhängiger Aufbewahrung und abweichender Ausfalldomäne.
   Nutze getrennte Namespaces oder Repositories und Credentials mit
   auf ihren Zweck begrenzten Rechten. Der Prüfer erhält Lesezugriff;
   Retention und administrative Löschrechte bleiben getrennt. Unterscheide
   im Katalog NAS/Freigabe, Backup-Dienst und unabhängige Kopie. Prüfe für
   ein externes vServer-Ziel nutzbaren Speicher, Durchsatz, Netzpfad und
   unterstütztes Backend vor der Freigabe.
3. Plane Backups mit Wartungsfenstern, Bandbreiten-, Kapazitäts- und
   Parallelitätsgrenzen pro Ziel/Standort. Unterscheide beobachtete native
   PVE/PBS-Zeitpläne von Steward-verantworteter Ausführung. Bei Übernahme
   eines Plans gilt FL03. Ein voller oder nicht erreichbarer Store löst
   einen sichtbaren Zustand mit Rückstau aus.

**Check/done**: Gültige Überschneidung von PVE- und Anwendungsbackup sowie
Zielablehnung bei fehlender Kapazität, unzulässigen Rechten,
doppelter Zeitplanverantwortung oder fehlendem Schutzumfang.
Ein Geräte- oder Linux-Anschluss ohne Backup-Fähigkeit ist im Katalog
als eigene Deckungslücke identifizierbar.

## BK10 — Native PBS-Sicherung, Restic und Offsite-Evidenz

**Voraussetzung:** BK09. **Einstieg:** PX03-Task-Abgleich und
RC1-Backup-Jobs mit dauerhaften Phasen.

1. Führe am vorgesehenen PVE-Ziel ein natives Gastbackup zu PBS aus und
   gleiche UPID und konkrete PBS-Snapshot-Identität ab. Erfasse Konsistenzmodus,
   Sicherungsumfang und tatsächlichen Abschluss. Führe den Linux-Pfad über
   genehmigte RC1-Erfassung, Upload und Integritätsprüfung zu Restic aus.
   Die Gastkonsistenz hängt vom beobachteten Workflow und seinen
   Voraussetzungen ab.
2. Repliziere PBS-Snapshots über einen freigegebenen Offsite-Pull mit
   separater Aufbewahrung ohne Löschweitergabe. Restic sichert auf ein
   unabhängiges freigegebenes Repository; wenn die Richtlinie zwei Kopien
   verlangt, erhält jede ihren eigenen Abruf-/Integritätsnachweis.
   Erfasse die externe Kopie, ihre Integritätsprüfung und ihr Alter
   getrennt vom ursprünglichen Snapshot.
3. Zeige pro Schutzobjekt letzten Abschluss, nächste Ausführung, Warteschlange,
   letzte externe Kopie, letzte Prüfung, Fehlerphase und RPO-Verletzung.
   Nach Scheduler- oder Verbindungsabbruch werden vorhandene Artefakte
   erkannt und nur sichere, abgleichbare Schritte erneut ausgeführt.

**Check/done**: Echte PVE/PBS- und RC1/Restic-Aufträge mit belegter
Nutzdatenzuordnung und einer unabhängigen Kopie. Prüfe fehlgeschlagenen
Sync, exklusiven Zielzugang und fortbestehende externe Kopie nach Verlust
des primären Testartefakts. Backup-Erfolg und Restore-Test bleiben
getrennte Ereignisse.
[PBS Remotes und Sync](https://pbs.proxmox.com/docs/managing-remotes.html) ·
[Proxmox-Datensicherung](https://github.com/proxmox/pve-docs/blob/master/vzdump.adoc)

## BK11 — Wiederherstellung aus externem Backup

**Voraussetzung:** BK10 und separat autorisierte Restore-Ziele.
**Einstieg:** bestehende Restore-Drills und PVE-Task-Abgleich.

1. Erzeuge einen Restore-Plan mit Snapshot, Backend und Schlüsseln per
   Referenz, neuer Gast-/Zielkennung, Netz/Storage-Abbildung, Kapazität,
   Freigabe und Nutzdaten-Prüfschritten. Die Restore-Übung erstellt
   isolierte Gast- und Anwendungsziele. Umschaltung auf ein produktives
   Ziel erfordert eine gesonderte Betreiberentscheidung.
2. Stelle einen PVE-Gast aus einem externen PBS-Snapshot sowie ein
   Beispielprojekt aus dem unabhängigen Restic-Ziel wieder her. Simuliere
   dabei den Verlust des jeweiligen Primär-Backup-Pfads. Prüfe Start,
   Integrität und fachliche Nutzdaten. Für Gasttypen und Volumes ohne
   eigenen Test bleiben die Nachweise entsprechend begrenzt.
3. Halte eine Wiederanlaufanleitung außerhalb des Flottenzustands vor,
   einschließlich Zielidentitäten, Schlüsselwiederbeschaffung, Netzwerk
   und gestaffelter Wiederinbetriebnahme. Miss Alter des verwendeten
   Backups und Zeit bis zur erfolgreichen Nutzdatenprüfung.

**Check/done**: Zwei nachvollziehbare Restores (PVE/PBS und Linux/Restic)
vom unabhängigen Standort mit verifizierten Nutzdaten, Neustart und
gemessenem RPO/RTO. Falscher Schlüssel, Zielkonflikt und fehlende
Kopie ergeben einen gesperrten oder fehlgeschlagenen Restore mit
konkreter Ursache.
