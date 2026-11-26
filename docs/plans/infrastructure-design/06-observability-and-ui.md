# 06 · Dashboard, Topologie, Metriken und Bedienung

Karte IN03 in [Infrastruktur](../infrastructure.md), FL01–FL03 für
Identitäten und Berechtigungen. Stand der Recherche 2026-11-24.
Die Oberfläche soll beantworten, was läuft, wo es liegt, was davon
abhängt, wann es zuletzt geprüft wurde und welche Aktion verfügbar ist.

## Vergleich: Inventar, Telemetrie und Graph

| Ansatz | Gut geeignet für | Grenze und Wahl |
|---|---|---|
| Native PVE/PBS-Daten einschließlich RRD | VM-/LXC-Platzierung, PVE-Zustände, CPU/RAM/Storage im vorhandenen Datenbestand | Primärquelle für PVE. IN03 übernimmt Einheiten und Auflösung und normalisiert Anzeigen. [PDM Remote und RRD](https://pdm.proxmox.com/docs/remotes.html) |
| NetBox-artiges bewusst gepflegtes Inventar | Standorte, Geräte, Netze, Verkabelung und beabsichtigte Struktur | Der deklarierte Zustand hat eine andere Herkunft als Runtime- und Health-Beobachtung. Ein späterer Import kann diese Herkunft bewahren. [NetBox Einführung](https://netbox.readthedocs.io/en/stable/introduction/) |
| Integrierte Zeitreihen und Events mit begrenzter Aufbewahrung | Aktuelle Verläufe mit derselben Ressource, Berechtigung und Zeitachse wie Jobs | Kleine Samplings, aggregierte Langzeitintervalle und Abfragegrenzen genügen für das erste Profil. Rohtelemetrie bleibt außerhalb des Quorum-Stores. |
| Prometheus/Grafana oder OpenTelemetry | Vorhandene lange Aufbewahrung und detaillierte Messungen, Standards für Typ, Einheit und Herkunft | Optional anschließen, wenn Zielberechtigungen bis zur Abfrage durchgesetzt werden. Ein externer Dashboard-Link hat seinen eigenen Zugriff. [Prometheus Metriknamen](https://prometheus.io/docs/practices/naming/) · [OpenTelemetry Resources](https://opentelemetry.io/docs/specs/semconv/resource/) · [Grafana Datenquellen](https://grafana.com/docs/grafana/latest/administration/data-source-management/) |
| Fokusgraph auf relationalen Kanten | Bedienbare Sicht auf wenige Nachbarn und Pfade, gemeinsames Rollenfilter mit Listen und Suche | Erste Wahl. Primäre Datenhaltung und API bleiben unabhängig von der JS-Graphbibliothek. |
| Graphdatenbank oder vollständiges Rendering der Flotte | Tiefe Ad-hoc-Traversierung und großflächige Graphanalysen | Höherer Betriebs-, Abfrage- und Accessibility-Aufwand. Erst bei gemessenem Mehrbedarf. |

Listenansicht und Graph sind gleichwertige Zugänge zur selben Projektion.
IN03 beginnt mit einer gefilterten Liste, einem Detail und einem
Fokusgraphen für den gewählten Knoten. React Flow bietet
Tastaturfunktionen und beschriftbare Knoten. Cytoscape.js bietet
Graphalgorithmen und ein anderes Renderingmodell. Die Auswahl nach
kleinem Browser-Prototyp bewertet Fokuspfad, Bedienung, Reflow, dichte
Kanten und vorhandene React-Integration. Das Datenmodell funktioniert
mit beiden. Bibliotheksauswahl erfordert keinen Laufzeitdienst.
[React Flow Accessibility](https://reactflow.dev/learn/advanced-use/accessibility) ·
[Cytoscape.js](https://js.cytoscape.org/) · [WCAG 2.2](https://www.w3.org/TR/WCAG22/)

## Projektion und Quellenvertrag

Die Quellen liefern Objekte, Beobachtungen und Beziehungen. Eine
Beobachtung enthält Typ, Ressourcengeneration, Scope, Zeit der Beobachtung,
Eingangszeit, Herkunft, Qualitätszustand und optional Zeitauflösung
oder abgedeckten Bereich. Ein Graph speichert Kanten mit eigenem
Zeitraum und Beleg. Eine Aktualisierung einer Quelle darf die
Bestätigungen einer anderen Quelle nicht überschreiben.

| Kante | Bedeutung | Herkunft | Beispiel |
|---|---|---|---|
| `hosts` | Beobachtete physische oder virtuelle Zuordnung | PVE oder registrierter Linux-Agent | PVE-Knoten beherbergt QEMU-VM. |
| `attached_to` | Beobachtete oder konfigurierte Netz-/Speicherzuordnung | PVE-Konfiguration, registrierter Connector | Gast hängt an Bridge/VLAN oder Storage. Dies beweist keine durchgehende Erreichbarkeit. |
| `reachable_from` | Ergebnis eines konkreten Protokollchecks | Checkquelle mit Site, Zeit und Transport | Externer vServer erreicht einen freigegebenen HTTPS-Dienst. |
| `depends_on` | Fachliche oder logische Abhängigkeit | Betreiberdeklaration oder belegter Anwendungsvertrag | App verwendet eine NAS-Freigabe. |
| `backs_up_to` | Bestand einer geplanten Policy und Status des konkreten Datenpfads | PBS/Restic, Policy und Quittung | LXC hat eine externe PBS-Kopie mit letzter Prüfung. |
| `eligible_on` | Geprüfte mögliche Platzierung | Native HA-Regel plus Eignungsbefund | PVE-Gast kann auf einem bestimmten NUC starten. |
| `shares_failure_domain` | Dokumentierte gemeinsame Ausfallursache | Site-/Gerätezuordnung mit Herkunft | NUC und NAS teilen Switch oder Strompfad. |

Alle Kanten zeigen mindestens **beobachtet**, **deklariert** oder
**abgeleitet mit Nachweis**. Eine Bridge-Zuordnung begründet keine
Anwendungssitzung. LLDP könnte später physische Nachbarn melden und
würde als L2-Quelle mit eingeschränkter Abdeckung geführt.
Die Existenz einer IP weist keinen Dienstbesitz und keine L3-Policy nach.
[IEEE 802.1AB-2026](https://standards.ieee.org/ieee/802.1AB/11787/)

| Zustandswert | Darstellung und Wirkung |
|---|---|
| Zustand aktuell und vollständig | Neben Zustand, Quelle und Zeitpunkt sind passende Aktionen verfügbar. Executor prüft bei Auftragserstellung erneut. |
| Zustand zuletzt bekannt, inzwischen veraltet | Letzten Beobachtungszeitpunkt nennen. Betroffene Aktionen brauchen frische Evidenz. Diagramm enthält Lücken. |
| Quelle nicht erreichbar | Erreichbarkeit je Beobachtungspunkt anzeigen. Die tatsächliche anwendungsspezifische Gesundheit bleibt gegebenenfalls unbekannt. |
| Geringere Abdeckung oder Recht entzogen | Keine unberechtigten Objekte, Kanten, IDs, Event-Zeilen oder aggregierten Summen ausliefern. |
| Beobachtete Null | Echte Null mit Einheit zeigen. Fehlende Beobachtung erhält einen eigenen Zustand. |

## Bildschirm- und Analysepfade

1. **Flottenübersicht.** Gliederung nach Site und PVE-Instanz,
   aktive Alerts/Aufträge, frische Ressourcen und gezielt markierte
   Quellenlücken. Filter für Standort, Typ, Zielgruppe, Zustand und
   Zeit. Sortierung nach Handlungsbedarf und dann stabiler ID.
2. **Gast- und Hostdetail.** Konfiguration und Ist-Zustand,
   tatsächliche Platzierung und letzte Änderung, Ressourcenkurven,
   Aktionen, Historie und externe Backup-Evidenz. Ein Action-Dialog
   zeigt Ziel, Auswirkung, erwartete Unterbrechung und Planrevision.
   Er bietet die tatsächliche Execution-Quittung nach Apply.
3. **Topologie.** Start im Umfang der gewählten Site oder Ressource.
   Standardansicht in Hierarchie `Site → PVE-Instanz → Knoten →
   Gast → Dienst`. Einblendbar sind Netz, Speicher, HA-Ziele,
   Backup, fachliche Abhängigkeiten und Ausfalldomänen. Eine
   Tastaturroute und ein Listenpfad zeigen dieselben Informationen.
4. **Backup und Dienste.** Jobs und Datenstände pro Backend.
   RPO-/RTO-Ziel getrennt vom letzten Messwert. CP03 zeigt
   Rolleninhaber, Datenstand jedes Standbys, ausgeschlossene
   Kandidaten und Quorumzustand. Der Ausfallgrund ist textlich
   sichtbar und nicht allein durch Farbe codiert.

**Beispielablauf.** Eine HA-VM zieht von NUC A nach B. Die Identität
der VM bleibt erhalten, das Dashboard wechselt die aktuelle
Hosting-Kante und bewahrt die frühere als Ereignis. Die Bridge-
Zuordnung kann gleich bleiben. Eine auf dem Pi gespeicherte
Freigabe der Anwendung hat einen eigenen Erreichbarkeitszustand.
Der externe vServer meldet seinen eigenen HTTPS-Check. Wenn das
Pi-NAS offline ist, zeigt die Oberfläche betroffene Freigaben und
Sicherungspfade. Ein funktionierender PVE-Gaststart bleibt sichtbar.

## Metrikvertrag und Volumen

- Zulässige Werte pro Adapter sind begrenzt und typisiert. Gauges
  erhalten Einheit und zulässigen Bereich. Counter brauchen
  Reset-Erkennung. Prozentwerte haben eine dokumentierte Basis,
  zum Beispiel VM-Limit oder Node-Kapazität. Keine Passwort-,
  Anfragekörper- oder unkontrollierten freien Labelwerte.
- Polling im Zielnetz, Batch-Abruf, kleine Seiten und ein Budget
  pro Quelle. Bei wiederholten Fehlern nutzt die Sammlung
  begrenzten Backoff. Die Frischegrenze bleibt auswertbar.
  Die Backoff-Phase erscheint zusammen
  mit dem letzten Beobachtungszeitpunkt.
- Beispielrechnung mit 100 Gästen, fünf Werten je Gast und einem
  30-Sekunden-Intervall. Das erzeugt 10,08 Millionen Samples pro
  Woche. Bei fünfminütigen Rollups kommen für 30 Tage 4,32
  Millionen hinzu, solange dieselben fünf Zeitreihen erhalten
  bleiben. Erfassungsumfang und Retention werden vermessen.
  IN03 priorisiert ein kurzes Detailfenster und länger aggregierte
  Sicht. Belegt ein vorhandenes PVE-RRD die benötigte Kurve,
  kann der Adapter daraus lesen.
- Berechtigung vor Projektion und Aggregation, einschließlich
  Autocomplete, Export, Metrik-Labels und Event-Page. Cache-Keys
  verwenden Rollen-/Scope-Revision und Filter. Eine Kante in
  einen unberechtigten Scope bleibt vollständig verborgen.
  Clientseitiges Ausblenden reicht für private Flottendaten nicht aus.

## Browser- und Betriebsabnahme

IN03 setzt Fixture für mindestens 100 Gäste, acht PVE-Knoten, NAS
und zwei Linux-vServern ein. Eine zweite Fixture prüft eine einzige
PVE-Instanz; eine weitere mehrere Instanzen ohne HA. Reale
Stichproben vergleichen die sichtbaren Werte und Quellen mit PVE,
dem NAS-Sensor und dem Agenten. Prüfungen decken Migration,
WAN-Störung, verzögerte Beobachtung, Scope-Wechsel, Navigation und
Tastaturbedienung ab. Messbedingungen, Budgets und Zielwerte für
Geschwindigkeit gehören in [Abnahme und Iterationen](08-delivery-and-iterations.md).
