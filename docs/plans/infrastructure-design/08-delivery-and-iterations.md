# 08 · Abnahmeplanung, Upgrade und Betrieb bis RC2

Karten PX01–IR02 im [Fahrplan nach RC1](../../post-rc1.md).
Stand der Recherche 2026-11-24. Diese Datei konkretisiert die Messungen
innerhalb der vorhandenen Karten. Der [RC1-Fahrplan](../../goal.md)
behält die Reihenfolge, Budgets und Regeln. Weitere Produktiterationen
stehen in [Ausbaustufen nach RC2](10-follow-up-iterations.md).

## Fortschritt in prüfbaren Produktständen

| Stand | Benutzbare Fähigkeit nach Abnahme | Voraussetzungen und Entscheidung |
|---|---|---|
| M9: Ein PVE-Host | Nativ installierter Agent, lokale Bedienung, QEMU/LXC und nachgewiesene Gastaktionen | S01-Freigabe, geeigneter PVE-Testhost, bekannte PVE-API- und Paketversion. UI und CLI aus demselben signierten Build prüfen. |
| M10: Flotte | Einzelhosts und bestehende PVE-Instanzen in einer Oberfläche, gemeinsame Richtlinien und verlässliche Ownership | Einzelne Steuerung mit Recovery. Abnahme mit mindestens zwei autorisierten Instanzen und gleichen VMIDs. |
| M11: Backup und Recovery | Sicht auf Schutzumfang, Fehler, Kopien und tatsächliche Restores | Für Restic freigegebene B08-Kette. Externen PBS- und Restic-Zugang und reale Wiederherstellungsziele rechtzeitig prüfen; Deckungslücke kann unabhängig von Implementierung offen bleiben. |
| M12: PVE HA | Native Gastaufnahme, Wartung, Eignung und reale Wiederanlaufbelege | Geeignete drei physische Testknoten, ausgewähltes Storage-Profil und Backup-Belege. |
| M13: Gemischte Flotte | PVE, Linux, Gerät, NAS, Graph, Metriken, private Scopes | Zwei echte Linux-Clients mit getrenntem Netzpfad, reale NAS-/Gerätesicht sowie passende Browser- und API-Fixtures. |
| M14: Steuerungs-Hochverfügbarkeit | Opt-in 2-von-3-Quorum, Rollenwechsel, Hot-Standbys, gesicherte Übergabe externer Jobs | CP01 Snapshot, Replay und Wiederanlauf; CP02 Nachweis vor CP03-Verfügbarkeitsfreigabe. |
| M15: RC2 | Integrierte Referenzflotte, Folgeinstallation aus Release, Wiederherstellung und konkrete Support-Matrix | Qualifizierte lokale und externe Testziele, Schlüssel außerhalb des Verbunds, signiertes Release und Rückkehrpfad. |

Nach jedem Stand kann der erprobte Umfang zusammenhängend demonstriert
werden. Vorzeitige Kombinationen erhalten dokumentierte Capability-
Grenzen. M14-Quorum ist ein eigenes opt-in Profil, während M9
weiterhin ohne einen externen Datenbankdienst funktioniert.

## Ebenen der Evidenz

| Ebene | Eignet sich für | Geltungsbereich |
|---|---|---|
| Typisierte Verträge und Fake-Uhr | Zustandsübergänge, Kopfkonflikt, Richtlinien, Datensyntax, Deduplizierung, Write Claim und Queue-Verhalten | Kein Nachweis für native API-Wirkung oder Host-Isolierung. |
| Browser und synthetische Topologie | Tastaturpfad, Rechte auf Graph, Suche, Details, Sortierung, Dashboard-Frische und UI-Responsivität | Verwendet echte Browser-/API-Grenzen. Die Metrikquelle ist synthetisch. |
| Reale isolierte Integration | API-Version/Token/UPID, echte Datenpläne, PVE-LXC/QEMU, TLS/Konnektivität, getrennte Identitäten und Installation | PVE kann für solche Gates verschachtelt sein, soweit die native Wirkung sinnvoll beobachtbar ist. |
| Physisches Lab | Hostverlust, Watchdog/Fencing, unabhängige Boot- und Storage-Pfade, RPO/RTO, NAS-/LAN-/WAN-Abhängigkeit | Gate gilt nur für qualifizierte Topologie und genehmigte Testziele. |
| Unabhängiger externer Restore | Offsite-Lesbarkeit, Schlüssel, isoliertes Ziel, Anwendungstest, dokumentierter RPO/RTO-Wert | Anwendbar auf tatsächlich getestete Daten, Backends und Standorte. |

[OpsTend Testebenen](../../testing.md) ·
[Jepsen Consistency Models](https://jepsen.io/consistency/models) ·
[NIST Contingency Planning Guide](https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final)

## Betriebsziele und Sicherheitsinvarianten

| Erwartung | Messmethode | Planwert / Auswertung |
|---|---|---|
| Inventarfrische | Zeit von bestätigter Änderung am Ziel bis zur sichtbaren korrekten Projektion. Gesonderte Probe für langsame oder ausgefallene Quelle. | Normalbetrieb innerhalb 120 s. Verzögerung und Beobachtungsabdeckung dokumentieren. |
| Bedienbarkeit bei 100 Gastobjekten | Reale Liste, Detail und Graph mit Scope, Cache-/Kaltzustand und reproduzierbarem Netzprofil. | Vorgeschlagen: p95 ≤ 1 s für paginierte Übersicht und ≤ 2 s für fokussierten Graph bei warmem Backend. Messbedingungen und Ergebnis getrennt angeben. |
| Lesbarkeit bei Ausfall einer aktiven Steward-Rolle | Von injiziertem Rollen-/Hostverlust bis autorisiertem Abruf über den vorgesehenen Zugang. | In den akzeptierten Testfällen ≤ 60 s bei weiterhin erreichbarem Quorum und geeignetem Zugang. |
| Sichere Schreibbereitschaft nach Steward-Failover | Von Ausfall bis zum bestätigten neuen Dispatch-Claim für eine zulässige Aktion auf unabhängiger Ressource. Native Taskzeit und erfolgreicher Readback sind eigene Messwerte. | Ziel ≤ 120 s bis Schreibbereitschaft. Blockierte Konflikte bleiben gesperrt und werden separat ausgewiesen. |
| Bestätigte Steueränderungen bei Einzelausfall | Vor Ausfall vom Quorum quittierte Revisionen, Claims und Eigentumswechsel mit dem verbleibenden autoritativen Stand vergleichen. | Keine quittierten Steueränderungen verloren in der ausgelobten Fehlertopologie. |
| PVE-Gastwiederanlauf | Knoten-, Quorum-, Fencing-, Start- und Anwendungszeitpunkt aus nativen Belegen. | Eigener Zeitwert pro Gasttyp, Daten-/Storage-Profil und Ausfall. |
| Offsite-RPO/RTO | Alter des geprüften Restore-Punkts. Abschnittszeiten für Zugang, Übertragung, Wiederaufbau und fachliche Prüfung. | Anfängliches RPO-Ziel 24 h je freigegebener Schutzklasse. RTO aus realer Messung und vereinbartem Datenumfang. |

Die Perzentilidee setzt genug wiederholte vergleichbare Anfragen und
ein bekanntes Lastprofil voraus. Die realen Fehlerdrills liefern
Ereigniszeitlinien und obere beobachtete Fehlerzeiten. Ein kleiner
Stichprobenumfang liefert keine statistische Verfügbarkeitszusage.
[Google SRE Workbook: Implementing SLOs](https://sre.google/workbook/implementing-slos/)

**Sicherheitsinvarianten.** Nie zwei konkurrierende Steward-Claims mit
überschneidender Wirkung. Kein neuer autoritativer Claim ohne aktuelle
Generation und Mehrheitsbestätigung im Quorum-Profil. Bindung an
Ressourcengeneration und lokalen Sicherheitsrahmen. Unbekannte
native Seiteneffekte behalten die Sperre. Rollenbeginn und langsame
Außenwirkung sind verschiedene Ereignisse. Private Daten erscheinen
einschließlich Kanten, Zähler und Zeitreihen erst nach erfolgreicher
Autorisierung. Eine Verletzung bleibt ein Capabilities-Blocker,
auch wenn die Laufzeitziele erreicht sind.

## Gezielte Störfälle und Zuordnung

| Störung | Nachweis | Besitzer |
|---|---|---|
| Alte Freigabe nach Gast-Neuanlage, falscher Pool, neue Zertifikatsidentität | Abbruch vor Außenwirkung mit begründetem Konflikt. | PX02–PX03 |
| Offline-Ziel wechselt beim Wiederverbinden Policy, Source Scope ist teilweise | Kein alter Schreibauftrag, korrekte aktuelle Revision und sichtbare Beobachtungsdeckung. | FL01–FL03 |
| Backup-Store voll, geänderte Schlüssel oder Origin-Snapshot entfernt | Getrennter Copy-, Prüfer- und Restore-Zustand. Belegte unabhängige Kopie bleibt verwendbar. | BK09–BK11 |
| PVE-Minderheit, Gast-Storage nicht verfügbar oder Passthrough | Keine falsche Claim-/HA-Aufnahme. Native Recovery und Nutzdatenbeleg für qualifizierbare Zielknoten. | PH01–PH03 |
| Verstecktes Gerät, Scope-Entzug oder verspätete Source Events | Keine indirekten Details in Metriken, Graph, Suche oder Zählern. Historie und Frische stimmen. | IN01–IN03 |
| Alte CP-Rolle wacht vor einem bereits beanspruchten nativen Aufruf auf | Kein erneut erteilter Claim auf der Ressource; bekannte UPID wird verfolgt; unabhängige Jobs gehen weiter. | CP02 |
| Quorumverlust, volle Datenbank oder unvereinbare Rollenversion | Schreibbereitschaft sichtbar eingeschränkt, kontrollierter Recovery-Pfad mit Quittungen. | CP01–CP03 |
| NAS und WAN jeweils einzeln getrennt | Betroffene Ketten korrekt, lokale unabhängige Dienste weiterlaufend. Der reale Scope und die Restores bleiben nachvollziehbar. | IR01 |
| Vollständiger Steuerungsverlust, alte Credentials und offene Jobs bei Wiederaufbau | Neue Generation und verifizierter externer Snapshot, alte Pfade wirksam isoliert, abgeglichene native Ressourcen vor Wiederfreigabe. | IR01 |

Alle Bindungen an reale Hosts, VMs, externe Systeme und Test-Namespaces
werden in privaten Receipts mit Genehmigung und Wiederherstellungsweg
gehalten. Ein Lab übernimmt keine bestehenden RC1-Fixtures. Tests auf
echten Zielpfaden verwenden ausdrücklich dafür freigegebene Testdaten.

## Übergang aus RC1 und Rückkehr

1. Prüfe das tatsächlich signierte Archiv und die freigegebenen
   RC1-Capabilities. Sichere Konfiguration, referenzierte Secrets und
   zugehörige Restore-Quittung. Die Paketprobe belegt unveränderten
   Zweitlauf und Neustart auf einem eigenen Ziel.
2. Übernimm einen vorhandenen Host im Lesemodus. Vor der Übernahme
   von Writes müssen Konflikte im Head, der lokal angewandte Stand,
   die aktuelle Zuständigkeit und aktive Jobs abgeglichen sein.
3. Nutze bei Versionswechseln ein getestetes Kompatibilitätsfenster
   zwischen Steuerung, Agent und Executor. Der Empfänger erkennt
   unbekannte schreibende Semantik und verweigert sie. Lesepfade
   melden eingeschränkte Abdeckung. Erst kompatible Leser und
   Executor, dann der neue optionale Writer, danach Schema-
   Aufräumen in einem eigenen freigegebenen Wechsel.
4. Führe SQLite-Import nach CP01 mit pausierten Schreibern,
   bestätigten Revisionen, Ressourcenclaims und eindeutigem
   Start der neuen Autorität durch. Tests unterscheiden
   Rollback eines Pakets, Rückkehr der Eigentümerschaft und
   Restore des gesamten Steuerungszustands. Ein älteres Binary
   darf eine vorwärtsmigrierte Datenbank erst nach belegter
   Versionskompatibilität öffnen.
5. Protokolliere Build-Key-Identität, Artifact-Digest, SBOM,
   Provenance, Versionen, Capability-Auswahl und installierte
   Revision. Verifikation, Installations- und Rückfallbelege
   gelten für genau das freigegebene Archiv.

[Kubernetes: Beispiel für explizite Version Skew Policy](https://kubernetes.io/releases/version-skew-policy/) ·
[SLSA Provenance](https://slsa.dev/spec/v1.2/provenance) ·
[OpsTend Release-Karte S01](../repositories-release.md#s01--verifiable-signed-release-for-an-accepted-feature-subset)

### Support-Matrix und Ergebnisdarstellung

Veröffentliche pro Capability Versionen, Architektur, Installationstyp,
Rollen, Netzwerk-/Storage-Voraussetzungen, Art des Tests sowie
Sicherheits- und Recovery-Nachweise. Einzelhost, gemischte Flotte
und Quorum-Profil bekommen getrennte Ergebnisaussagen. Pi als
agentenlose NAS-Quelle und volle Arm64-Installation sind verschiedene
Fähigkeiten. Der gemeinsame Release-Schnitt enthält die akzeptierten
Funktionen mit belegter Reichweite. Offene Gates behalten ihren
Abnahmestatus und begrenzte aktivierbare Oberfläche.
