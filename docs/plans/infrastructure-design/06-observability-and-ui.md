# 06 · Dashboard, Topologie, Metriken und Bedienung

Karten UI01, IN03 und NX01–NX04 in [Infrastruktur](../infrastructure.md),
FL01–FL03 für Identitäten und Berechtigungen.
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
Fokusgraphen für den gewählten Knoten. Der Bedienentwurf prüft dafür
eine Platzierungsansicht mit kombinierbaren Ebenen für Verkabelung,
Netzregeln und externe Zugänge. Ressourcenvergleiche bleiben in Tabellen, Messverläufe in
Zeitreihen und Aufträge in einer chronologischen Ansicht.
[Bedienentwurf und Browseraufnahmen](../../design/rc2-webapp/README.md) ·
[WCAG 2.2](https://www.w3.org/TR/WCAG22/)

## PlantUML und Excaliplant in der Webapp

1. Die API liefert für Flotte, Standort oder Einzelobjekt einen
   berechtigten Ausschnitt mit stabilen Objekt- und Kanten-IDs,
   Beziehungstyp, Herkunft und Beobachtungszeit. Standortgruppen und
   zusammengefasste Zähler begrenzen die globale Übersicht. Die
   fokussierte Ansicht lädt die passenden Nachbarn und Ebenen nach.
2. Ein Serializer erzeugt aus dieser Projektion ein PlantUML-
   Deployment-Diagramm mit intern vergebenen Aliasen. Anzeigenamen
   gehen begrenzt und als Text in feste Vorlagen ein. Der generierte
   Quelltext nutzt einen festen Syntaxumfang ohne Includes oder
   Benutzermakros. Platzierung, Kabel, Netzzuordnung, Regel und
   geprüfte Erreichbarkeit behalten ihre jeweilige Bedeutung.
3. Excaliplant rendert aus dem PlantUML-Text eine SVG-Karte für die
   laufende Ansicht und bei Bedarf eine bearbeitbare Excalidraw-Szene
   für den Export. IN03 prüft zuerst einen lokal gebündelten,
   bedarfsgeladenen Web Worker nach dem Vorbild der Excaliplant-
   Webapp. Die Anwendung übergibt Farbschema, Größen- und Zeitbudgets.
   Ein neuer Zielkontext entwertet ältere Renderergebnisse. Bei einem
   Renderfehler bleibt die Listenansicht mit den aktuellen Daten bedienbar.
   [Excaliplant Web Worker](https://github.com/grethel-labs/excaliplant/blob/main/docs/site.md#how-rendering-works)
4. React hält Auswahl, Zoom, Filter und Detailpanel. Excaliplant rendert
   interaktives Inline-SVG. Die Browser-Hooks binden Hover, Klick und
   Tastatur an die Karte. Knoten-Aliase und Connector-Primitiven tragen
   Hook-IDs, die auf die stabilen Fach-IDs des Inventars abgebildet
   werden. Die Zuordnung wird auch bei identischen Anzeigenamen geprüft.
   [Excaliplant-Hooks](https://github.com/grethel-labs/excaliplant/blob/v1.14.2/docs/hooks.md)
5. Eine Änderung aus dem Detailpanel erzeugt einen typisierten, an
   Ziel und Revision gebundenen FL03-Entwurf. IPv4-Adresse, Endpunkte
   und Beziehungsdaten ändern zunächst die Vorschauprojektion. Die
   Karte rendert diese Projektion erneut und markiert geplante Werte.
   Bestätigtes Apply und neuer Readback aktualisieren die beobachtete
   Projektion. Layout und Exporte haben keine Schreibwirkung auf die
   Infrastruktur.

Die [Beispieldatei in PlantUML](../../diagrams/src/15-rc2-infrastruktur.puml)
und die [Excaliplant-Ausgabe](../../diagrams/out/svg/15-rc2-infrastruktur.svg)
zeigen den Weg von externen Zugängen über einen VPN-Tunnel zu Diensten
am Standort. Dazu kommen physische Switchlinks, VLANs,
Firewall-Regel, PVE-Gäste, Linux-Container, Passthrough und NAS.
Der produktive Ausschnitt zeigt die jeweils autorisierten Live-Daten.

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
| `physical_link` | Physische Gegenstelle und belegte Linkrate | UniFi, autorisierter Connector oder bestätigte Dokumentation | Switchport verbindet Host. Gemessener Verkehr hat seinen eigenen Zeitraum. |
| `assigned_device` | Zugeteilte oder durchgereichte Hardware | Native PVE-/Host-Beobachtung oder markierte Dokumentation | VM verwendet die GPU, einen zugehörigen HDMI-Ausgang oder ein USB-Gerät. |
| `allowed_by` | Wirksamer Regelausschnitt für benannte Richtung und Scope | UniFi oder qualifiziertes Firewallprofil | Eine Regel erlaubt ausgewählten Verkehr zwischen zwei VLANs. |
| `published_via` | Gewünschte oder extern bestätigte Veröffentlichung | NX02-/NX03-Job und unabhängiger Check | Website läuft über Proxy und VPN. Portalzugriffe zeigen ihre eigene Autorität. |
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
Ein beobachteter Client hat einen eigenen Verwaltungsstatus.
Flottensummen zählen physische Ressourcen und geteilten Storage pro
stabiler Quellidentität einmal. Zuteilungen, Reservierung und
Nutzung erscheinen getrennt von Hardwarekapazität.
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
Tastaturbedienung ab. Der Produktionsbuild prüft zusätzlich den lokalen
Renderpfad unter der CSP, den Themewechsel, die Zuordnung der Details
bei identischen Namen sowie den Listenpfad bei einem Renderfehler.
Messbedingungen, Budgets und Zielwerte für Geschwindigkeit gehören in
[Abnahme und Iterationen](08-delivery-and-iterations.md).
