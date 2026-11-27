# OpsTend Bedienentwurf und Browseraufnahmen

Der [klickbare RC2-Entwurf](index.html) öffnet sich lokal im Browser. Er zeigt
einen Beispielstandort mit Proxmox, Ubuntu, UniFi und NAS sowie einen externen
Linux-Host. Suche, Geltungsbereich, Navigation und Farbschema wirken auf
diese Beispieldaten. Die Demo speichert die Änderungen am Inventar im Browser.

- **Betrieb** beginnt mit offenen Störungen und anstehenden Entscheidungen.
  Verfolge Zorecs Prüfung für Sensorik oder prüfe die HTTPS-Freigabe für
  Medien. Eine Freigabe oder Ablehnung in der Demo erscheint im Verlauf.
  Anwendung, externer Prüfbeleg und Rücknahme von Medien haben eigene
  Schritte. Unter **Netzwerk → HTTPS-Veröffentlichungen** sind Ziel,
  Proxy und WireGuard-Pfad auch vom jeweiligen Dienst aus erreichbar.
  Über **Geltungsbereich** siehst du die Fälle für eine einzelne Maschine.
  Beim Wiederanlauf von Sensorik lassen sich ein erfolgreicher und ein
  fehlgeschlagener Health-Beleg simulieren. Nach einem Fehlschlag
  erscheint eine Entscheidung für eine erneute Prüfung im Betrieb.
  Im Auftrag verlinkt **Betroffene Ressourcen** den Dienst, den Host,
  das Dienstnetz, die Karte und das gefilterte Protokoll. Bei der
  Medien-Freigabe öffnet der Tunnel-Link den registrierten WireGuard-Pfad
  auch aus dem Bereich `nuc-a`. Mobil führt **Zur Auftragsliste** zur Auswahl.
- **Protokoll** zeigt ausgeführte Auftragsschritte im gewählten Bereich.
  Filter lassen sich über den Direktlink wieder öffnen. Dienst-, Port-
  und Host-Ticker führen zum jeweiligen Ausschnitt.
- **Systemübersicht** verbindet die Fachbereiche für die Flotte oder
  den gewählten Host. **Gesamttopologie öffnen** blendet die Verkabelung,
  Netze und Regeln sowie VPN- und Zugangspfade gemeinsam ein.
  Die Hostliste zeigt Erreichbarkeit mit Beleg, Betriebszustand und CPU-
  Messstand und führt zu Hostdetail, Überwachung oder Dienstliste.
  In **Betrieb** stehen aktuelle Nutzung, Messabdeckung und bekannte
  Kapazität getrennt. Hostaufnahme ergänzt den erfassten Bestand.
- **Überwachung** vergleicht CPU, RAM und lokalen Speicher für die Flotte
  oder einen Host. Öffne **host-b** für eine CPU-Spitze und eine Messlücke,
  **edge-01** für veraltete Werte oder **nuc-d** für einen Zeitraum ohne
  Messung. Die Auswahl bleibt im Direktlink. Vom Verlauf gelangst du zur
  Maschine, zum gefilterten Protokoll und zu offenen Vorgängen.
- **Dienste** zeigt Anwendungen neben Steuerung, Webapp, Zorec und IPA.
  Öffne eine VM, ein LXC oder einen Podman-Dienst für Platzierung,
  Laufzustand, Health und Auftragsprotokoll. Ein geordneter Stopp oder Start
  zeigt zuerst Ziel und Wirkung. Nach Bestätigung landet der Auftrag in
  **Änderungen**. Dort bekommst du getrennte Schritte für Ausführung,
  Antwortverlust, Abgleich und Readback. Im Gastdetail führt
  **Laufzeitauftrag öffnen** dorthin zurück.
  **Gast aus Vorlage** ist auch vom Host aus erreichbar. Proxmox bietet
  QEMU und LXC, Linux das Podman-Profil. Bestätige die vorgemerkte Anlage
  im Auftrag, um den simulierten Laufzustand am Gast zu sehen.
  **Ausfall simulieren** zeigt eine Wahl und eine Ersatzinstanz der
  Steuerung. Beides verändert die Platzierung für die Karte.
- **Proxmox-Inventar** liest in der laufenden lokalen Demo den nativen
  PX02.2-Vertrag mit Beispieldaten über `GET /inventory` und
  `GET /guests/<vmid>`. Aus Inventar, Host, Dienst, Karte und
  **Configuration → Integrationen** gelangst du zum jeweiligen Lesebeleg.
  **Demo-Lesestand** wechselt zwischen sichtbarem Inventar, eingeschränktem
  Token, abgelaufenem Snapshot und nicht verfügbarer Quelle.
- **Neuer Dienst** öffnet Zorec rechts unten. Wähle Repositories aus und
  benutze den geführten Dialog oder den manuellen Editor. Die Bestätigung
  erzeugt einen Auftrag im Beispielinventar.
- **Zorec fragen** zeigt den Gesprächsverlauf. Fragen zu Vorgängen und
  Netzadressen greifen auf den aktuellen Demo-Kontext zu. Die Antworten
  führen zu Vorgang, Karte oder Deployment-Entwurf.
  **Auf dieser Seite** ergänzt die Standards um Fragen zur aktuellen Ansicht.
  „Navigier mich zu deinen Berechtigungen“ öffnet **Configuration → Zorec
  und KI** bei offenem Chat und aktualisiert die Vorschläge. Über den
  Antworttexten steht **Zorec**. Host und Modell stehen unter **Ablauf ansehen**.
  Über **+** am Eingabefeld öffnet sich der **Fragebereich**. Dort kannst du
  allgemeine Fragen oder Webquellen ausdrücklich wählen. Mit freigegebener
  Internet-Recherche verwendet die
  Demo Wikipedia und zeigt die Artikel zur Antwort. Für „Haben die Services
  alle gesyncte Zeiten?“ bietet Zorec eine lesende Beispielprüfung an.
  Der Admin-Chat merkt sich den zuletzt gewählten Modus im Browser. Beim
  Wechsel zwischen **Admin Lesen** und dem violetten **Admin Edit** bleibt
  der Verlauf sichtbar. Die aktive Shell bestimmt, welche früheren Antworten
  ins Modell eingehen und welche Aktionen verfügbar sind.
  Im Menü **Chats** kannst du einen neuen Verlauf beginnen oder einen
  früheren Chat öffnen. Die Demo speichert standardmäßig zehn ältere Chats
  zusätzlich zum aktuellen Chat. Unter **Configuration → Zorec und KI →
  Chatverlauf** lässt sich die Aufbewahrung einstellen. Die Berichtsvorschau
  verwaltet ihre eigenen Chats.
  Über **Aktivität** öffnest du die Konsole neben dem Chat. Mit **Ablauf ansehen**
  kannst du zu einer früheren Antwort zurückspringen. Die Konsole zeigt für
  die lokale Demo die verwendete Shell, den Kontext, den Abgleich und die
  angebotenen nächsten Schritte. Am geschlossenen Chat zeigt Zorec den
  Betriebszustand des gewählten Bereichs mit Hintergrundfarbe, Symbol und
  Text. In einem ruhigen Bereich zwinkert er gelegentlich und döst nach
  45 Sekunden ein. Sein Blick folgt der Maus in seiner Nähe. Unter
  **Configuration → Zorec und KI → Gesten ausprobieren** lässt sich jede
  Reaktion neben dem laufenden Beispielbetrieb ansehen.
- Aus dem Dienst- oder Hostkontext kann Zorec eine Topologie-Markierung
  öffnen, ein Erklärdiagramm neben dem Chat zeichnen und es in einer
  späteren Antwort erweitern. **Diagramm** und **Aktivität** wechseln
  den Seitenbereich. Mobil wechselt die Ansicht innerhalb des Dialogs.
  Ein Klick außerhalb minimiert den Chat und erhält den Textentwurf.
  In Admin Edit kann ein Vorschlag für das Messintervall
  von Sensorik als gelb markierte Eingabe übernommen werden. In Host- und
  Dienstkonsolen unterstützen `@Zorec`, `@zorec` und `@chat` editierbare
  Befehlsentwürfe mit simulierter Konsolenausgabe.
- **Configuration → Zorec und KI** zeigt die wirksame Modellwahl. Auf dem
  lokalen Demo-Server lassen sich die freigegebenen Modelle von `cn-0001`
  abrufen und testen. Die Modellwahl für freie Chatfragen gilt nach dem
  Speichern für diesen Browser. Im Chat steht die Antwortquelle am Beitrag.
- **Modellvergleich** prüft zwei abgerufene Modelle anhand derselben
  drei Demo-Fälle. Der Bericht zeigt Einzelantworten und Dauer. Ein
  Modell kann für die Chat-Auswahl vorgemerkt und danach gespeichert werden.
- **Configuration → OpsTend-Updates** zeigt die Update-Richtlinie je
  Beispielinstallation. Ein neues Release führt zur Patch-Sicherung und
  zum Abgleich. Für einen Konflikt lässt sich ein Zorec-Vorschlag prüfen.
  Übernahme und Rückkehr zum gesicherten Stand finden im Browser statt.
- **Configuration → Hostverwaltung** nimmt den Beispielhost `linux-neu`
  mit vorhandenem Dienstbestand auf. Für jeden Dienst ist eine Entscheidung
  nötig. Die Vorschau prüft freigegebene CPU, RAM, Speicher und GPU gegen
  die Belegung. Danach erscheint der Host im Inventar und in der Topologie.
  Reset und Austritt zeigen den Verbleib der Dienste vor der Bestätigung.
  Die Bestandsaufnahme verwendet feste Beispieldaten.
  Bei einem verschobenen Dienst zeigt **Herkunft und Zuständigkeit** den
  Quellhost und den verknüpften Auftrag. Das gefilterte Protokoll bleibt mit
  den früheren Schritten zum Dienst verbunden.
- **Configuration → System-API** verwendet den lokalen Demo-Server für
  Testidentitäten, Chat-IDs, Nachrichten und eine typisierte Beispielaktion.
  **Direkt per API** plant die Sensorik-Prüfung mit einem Aktions-Testkonto
  ohne Chat. **Mit Zorec-Chat** bindet sie an eine Admin-Edit-Chat-ID und
  verknüpft den simulierten Auftrag mit dem Chatverlauf. HTTP-Status und
  Antwort sind sichtbar. Datensätze gelten für die Laufzeit des Demo-Servers.
- **Netzwerk** zeigt Geräte, physische Ports, VLANs und Zugangspfade als
  Tabellen. Ein Klick auf einen Port oder Tunnel wählt ihn in der Karte aus.
  Unter **Firewall und ACL** kannst du **NFS für Medien** öffnen. Die
  Vorschau stellt aktive und gewünschte Wirkung gegenüber. Der Entwurf
  erscheint in **Betrieb** zur Freigabe. Nach Bestätigung zeigt die Karte
  die vorherige Verbindungsprobe als historischen Beleg. Die
  Verwaltungs-ACL zeigt ihren Konfigurationsbeleg in einer Leseansicht.
  **Port öffnen** führt zur VLAN-Zuordnung. An P2 kannst du Access- und
  Trunk-Zuordnungen prüfen und in der Demo übernehmen. Der Uplink P1
  zeigt seine bestehende Zuordnung und den Grund für den Lesezugriff.
- Die eigene **Objektseite** bündelt Konsole, letzte Ereignisse und
  Hardware und Netz. Öffne **Fotos** für den Wechsel zur Web-UI-Vorschau
  oder **Sensorik** für die Einstellungen seines versionierten Adapters.
  Beim Anlegen aus einem Sensorik-Repository erscheinen dieselben Felder
  im geführten und manuellen Weg. Am laufenden Beispieldienst zeigt
  **Änderung prüfen** die Differenz. Nach dem Speichern steht sie auch
  im Eintrag unter **Änderungen**.
  **Adapter aktualisieren** zeigt am Beispieldienst die Feldumstellung für
  Version 1.1.0. Nach der Bestätigung kannst du Werte der neuen Version
  ändern oder den gesicherten Stand über **Adapter zurücksetzen** prüfen
  und wiederherstellen.
- **Topologie** rendert aus demselben Inventar. Wähle eine Ressource oder
  Verbindung auf der Karte. **Ganze Karte** zeigt den Ausschnitt vollständig.
  **Auswahl vergrößern** springt zum ausgewählten Element. Direkte
  Verbindungen sind auch bei ausgeblendeter Ebene auffindbar. Die
  Detailansicht zeigt, ob eine Kante einen Port, eine konfigurierte
  Beziehung oder einen geprüften Pfad darstellt. **Bearbeiten** öffnet die
  Felder. Eine Änderung wird als Entwurf dargestellt.
- **Configuration** bündelt Systemzugriff, Zorec/KI, Funktionen,
  Integrationen und Richtlinien. Wirkliche Systemaktionen folgen im Produkt
  dem gebundenen Auftrag mit Vorschau, Freigabe und Readback.
  Unter **Sprache** lassen sich Deutsch und Englisch für Oberfläche und
  Zorec getrennt wählen. Ein persönliches Demo-Profil erbt oder überschreibt
  jeden Wert unabhängig. Die Profile simulieren die Zuordnung zur Anmeldung.

Der [RC2-Fahrplan](../../post-rc1.md#ziel-und-reihenfolge) ordnet diese
Ansichten den Umsetzungskarten zu. Die [integrierte Abnahme](../../plans/infrastructure.md#ir01--integrierte-abnahme-der-referenzflotte)
verknüpft Live-Topologie, reale Aufträge, Zorecs Zustandsanzeige und
die Netz- und Wiederanlaufprüfungen.

## Welche Darstellung wofür

| Aufgabe | Darstellung | Grund |
|---|---|---|
| Wissen, wo eingegriffen werden muss | Handlungsbedarf mit Status, Ziel und nächstem Schritt. Wenige Kennzahlen geben den Umfang an. | Die Startseite zeigt zuerst, was der Betreiber entscheiden oder verfolgen kann. |
| Hosts, VMs, Container und Geräte vergleichen | Suchbare Tabelle und Maschine als Detailansicht. | Typ, Standort, Runtime, Zustand und Quelle lassen sich nebeneinander lesen und filtern. [Grafana Tabellen](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/table/) |
| Verstehen, was womit verbunden ist | Excaliplant-Karte mit **Platzierung** und schaltbaren Ebenen für **Verkabelung**, **Netz und Regeln** sowie **VPN und Zugang**. | Die Platzierung hält Standort und Host sichtbar. Port und ausgehandelte Linkrate gehören an den physischen Link. Fachliche Freigabe und gemessene Erreichbarkeit erscheinen mit eigener Beschriftung. [Grafana Knotengraphen](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/node-graph/) |
| Konkreten Netzpfad oder Passthrough prüfen | Beziehungsauswahl, Quellenpanel und Geräteliste. | Der genaue Port, das letzte Prüfdatum, die Gerätebindung und die Auswirkung einer Änderung brauchen lesbaren Text. [W3C Textalternativen für komplexe Grafiken](https://www.w3.org/WAI/tutorials/images/complex/) |
| Auslastung und freie Kapazität beurteilen | Zeitreihe für den Verlauf. Balken und Zahlen für einen aktuellen Wert samt Grenze oder Reserve. | Der Verlauf zeigt Schwankungen und Peaks. Der konkrete Zahlenwert erklärt die noch verfügbare Kapazität. [Grafana Zeitreihen](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/time-series/) |
| Einen Auftrag verstehen oder freigeben | Chronologischer Verlauf mit Ergebnis oben, danach Ziel, Auslöser und Prüfschritte. | Die Ansicht trennt einen ausgeführten Neustart von einer anschließend bestätigten Gesundheit. Zorec fasst denselben Vorgang im Betrieb zusammen. |
| Richtlinien und Anschlüsse bearbeiten | Wirksame Werte als Tabelle mit Herkunft, Bearbeitung als fokussiertes Formular. | Ein Betreiber kann Vererbung prüfen und beim Einrichten eines Ziels Schritt für Schritt vorgehen. |

Karte und Liste verwenden dasselbe Beispielinventar. Der Entwurf bietet
eine direkte Auswahl per Excaliplant-Hook und eine textliche Auswahl.
Im Produkt verwenden beide denselben autorisierten Ausschnitt.

## RC2 Browseraufnahmen

| Ansicht | Rendering |
|---|---|
| Betrieb mit offenen Störungen und Entscheidungen | [Betriebsübersicht](renderings/rc2-betrieb.png) |
| Übergabe an den Betreiber nach negativem Health-Beleg | [Eskalation](renderings/rc2-eskalation.png) |
| Fachbereiche und Hosts im selben Geltungsbereich | [Systemübersicht](renderings/rc2-systemuebersicht.png) |
| Hostvergleich und Messlücke | [Überwachung](renderings/rc2-ueberwachung.png) · [Mobiler Hostverlauf](renderings/rc2-ueberwachung-mobil.png) |
| Geräte, Ports, Netze und VPN-Pfade als Tabellen | [Netzwerk](renderings/rc2-netzwerk.png) |
| Anwendungen, Core-Dienste und Replikate | [Dienste und Deployments](renderings/rc2-dienste.png) |
| Gastansicht mit Laufzustand, Health und Auftragsprotokoll | [QEMU-Gast](renderings/rc2-gast.png) |
| Laufzeitauftrag während des Abgleichs | [Gastauftrag](renderings/rc2-gastauftrag.png) |
| Vorlage und Ziel für einen neuen Gast | [Gastanlage](renderings/rc2-gastanlage.png) |
| Typisierte Felder für einen Beispieladapter | [Sensorik-Einstellungen](renderings/rc2-adapter-einstellungen.png) |
| Vorschau einer Änderung mit altem und neuem Wert | [Änderungsentwurf](renderings/rc2-adapter-aenderung.png) |
| Versionswechsel mit Feldmigration und Rückweg | [Adapter-Update](renderings/rc2-adapter-wechsel.png) |
| VLAN mit Mitgliedern, Ereignissen und Verbindungen | [Netzdetail](renderings/rc2-netzdetail.png) |
| Port mit Linkbeleg und VLAN-Zuordnung | [Switchport](renderings/rc2-switchport.png) |
| Firewall-Regel mit Wirkung, Verbindungsbeleg und Vorschau | [Netzregel](renderings/rc2-netzregel.png) |
| Suche und Vergleich von Ressourcen | [Inventar](renderings/rc2-inventar.png) |
| Proxmox-Lesestand und einzelne Gastbelege | [Proxmox-Inventar](renderings/rc2-pve-inventar.png) · [Gastbelege](renderings/rc2-pve-gastbelege.png) |
| Eine Maschine mit Messkurve, Passthrough und Workloads | [Maschinendetail](renderings/rc2-maschine.png) |
| Hosts mit VMs, Containern und Core-Diensten | [Platzierung](renderings/rc2-platzierung.png) |
| Platzierung und alle Verbindungsebenen zusammen | [Gesamttopologie](renderings/rc2-gesamttopologie.png) |
| Geräte und physische Links | [Verkabelung](renderings/rc2-verkabelung.png) |
| VLANs, Firewall und Prüfpfade im dunklen Modus | [Netz und Regeln](renderings/rc2-netz-dunkel.png) |
| VPN, veröffentlichte Website und separates Portal | [VPN und Zugang](renderings/rc2-vpn-zugang.png) |
| Veröffentlichungspfad mit externem Beispielbeleg | [HTTPS-Freigabe für Medien](renderings/rc2-https-veroeffentlichung.png) |
| Zorecs Wiederanlauf in der Auftragsansicht | [Änderungen](renderings/rc2-aenderungen.png) |
| Health-Ereignisse für eine Maschine | [Ereignisprotokoll](renderings/rc2-protokoll.png) |
| Ein Entwurf vor der Ausführung | [Ausstehende Freigabe](renderings/rc2-freigabe.png) |
| Zugriffsmethoden und Systemkonfiguration | [Configuration](renderings/rc2-configuration.png) |
| Hostaufnahme und Ressourcenfreigaben | [Hostverwaltung](renderings/rc2-hostverwaltung.png) |
| Abgleich vor einem eigenen Versionswechsel | [OpsTend-Updates](renderings/rc2-eigenupdate.png) |
| Getrennte Zorec-Shells und optionale Berechtigungen | [Shell-Einstellungen](renderings/rc2-zorec-shells.png) |
| Vollautonomen Modus in der KI-Konfiguration aktivieren | [Autonomie](renderings/rc2-zorec-autonomie.png) |
| Zorecs Prüfung, Begründung und Quelle im Sensorik-Auftrag | [Entscheidungsbeleg](renderings/rc2-zorec-entscheidung.png) |
| Statusgesten mit Vorschau für Zorecs eigene Fehler | [Gesten ausprobieren](renderings/rc2-zorec-gesten.png) |
| Flottenrichtlinie und wirksame Host-Ausnahme | [Einstellungen](renderings/rc2-einstellungen.png) |
| Formularvorschau beim Anschluss eines Backup-Ziels | [Backup-Dialog](renderings/rc2-backup-dialog.png) |
| Zorecs Antwort zu einer laufenden Prüfung | [Gespräch mit Zorec](renderings/rc2-zorec.png) |
| Hostwartung mit wirksamem Fenster und Auswirkungen je Gast | [Wartungsvorschau](renderings/rc2-hostwartung.png) |
| Geltungsbereich und Ablauf einer Antwort | [Aktivitätskonsole](renderings/rc2-zorec-aktivitaet.png) · [Mobil in Dunkel](renderings/rc2-zorec-aktivitaet-mobil.png) |
| Live-Erklärdiagramm neben der Unterhaltung | [Diagramm](renderings/rc2-zorec-diagramm.png) |
| Die Betriebsübersicht auf dem Smartphone | [Mobile Ansicht](renderings/rc2-mobil.png) |

## Aktuelle Webapp

Die Aufnahmen zeigen die bestehende Anwendung nach Anmeldung an der lokalen
FastAPI-Testinstanz. In der Übersicht fehlt bei dieser Fixture die
Controller-Telemetrie. Die Konfigurationsaufnahme zeigt die geöffneten
Abschnitte des vorhandenen Formulareditors.
[Aktuelle Übersicht](renderings/ist-uebersicht.png) ·
[Aktuelle Konfiguration](renderings/ist-konfiguration.png)

## Renderings wiederholen

Der [Bedienentwurf](../../plans/rc2-webapp.md) und der
[technische Renderpfad](../../plans/infrastructure-design/06-observability-and-ui.md#plantuml-und-excaliplant-in-der-webapp)
sind die Grundlage für die spätere Live-Anbindung. Die Browseraufnahmen
lassen sich mit der gebündelten Excaliplant-Laufzeit für die Topologie und
der vorhandenen Playwright-Installation der Webapp erneut erzeugen.

```sh
npm --prefix docs/design/rc2-webapp/topology ci --ignore-scripts
npm --prefix docs/design/rc2-webapp/topology run build
node docs/design/rc2-webapp/render.mjs
```

Bei laufender lokaler Demo prüft und rendert derselbe Befehl zusätzlich
die Proxmox-Ansichten über HTTP.

```sh
OPSTEND_PVE_DEMO_URL=http://127.0.0.1:19083/ node docs/design/rc2-webapp/render.mjs
```
