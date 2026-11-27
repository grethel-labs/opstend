# Steward-Diagramme

Die Diagramme zeigen Abläufe auf einem verwalteten Linux-Host und das
Zielbild für die Flottentopologie. Die
[Architektur](../architecture.md) beschreibt die Schnittstellen.
[STATUS](../STATUS.md#card-state) belegt den Stand der Funktionsfreigaben und
Host-Abnahmen. Ein Diagramm eines Kandidaten beschreibt den vorgesehenen oder
bereits implementierten Pfad mit den dort dokumentierten Freigabegrenzen.

| Bereich | Diagramm | Excalidraw |
|---|---|---|
| Architektur | [Dienste und Vertrauensgrenzen](out/svg/00-gesamtbild.svg) | [Datei](out/excalidraw/00-gesamtbild.excalidraw) |
| Executor | [Prüfkette einer Anfrage](out/svg/01-executor-pruefkette.svg) | [Datei](out/excalidraw/01-executor-pruefkette.excalidraw) |
| Controller | [Selbstheilung und Eskalation](out/svg/02-selbstheilung.svg) | [Datei](out/excalidraw/02-selbstheilung.excalidraw) |
| Konfiguration | [Geprüfter Apply und Site-Deployment](out/svg/03-deploy-und-revisionen.svg) | [Datei](out/excalidraw/03-deploy-und-revisionen.excalidraw) |
| Kritisches Risiko (Kandidat) | [Exposition, Quarantäne und Freigabe](out/svg/04-kritisches-risiko.svg) | [Datei](out/excalidraw/04-kritisches-risiko.excalidraw) |
| Verifizierte Updates (Kandidat) | [Freigabe, Prüfung und Recovery](out/svg/05-update-pipeline.svg) | [Datei](out/excalidraw/05-update-pipeline.excalidraw) |
| Anwendungsbetrieb | [Lebenszyklus separat isolierter Anwendungen](out/svg/06-anwendungs-lebenszyklus.svg) | [Datei](out/excalidraw/06-anwendungs-lebenszyklus.excalidraw) |
| Repository-Deployment (Kandidat) | [Commit, Build, Validierung und Freigabe](out/svg/07-repo-deployment.svg) | [Datei](out/excalidraw/07-repo-deployment.excalidraw) |
| Wartung | [Zulassung im wöchentlichen Fenster](out/svg/08-wartungsfenster.svg) | [Datei](out/excalidraw/08-wartungsfenster.excalidraw) |
| Netzwerk | [Netzkante, Loopback und Egress pro UID](out/svg/09-netzwerk.svg) | [Datei](out/excalidraw/09-netzwerk.excalidraw) |
| Host-Dateien | [Konfiguration, Daten und Laufzeitzustand](out/svg/10-dateibaum.svg) | [Datei](out/excalidraw/10-dateibaum.excalidraw) |
| Sicherheit | [Bedrohungen und Schutzmaßnahmen](out/svg/11-bedrohungsmodell.svg) | [Datei](out/excalidraw/11-bedrohungsmodell.excalidraw) |
| Backups (Kandidat) | [Capture, Upload, Prüfung und Restore](out/svg/12-backup-nachweise.svg) | [Datei](out/excalidraw/12-backup-nachweise.excalidraw) |
| KI-Beratung (Kandidat) | [Scopes, Peer-UID und Budget](out/svg/13-inferenz-und-advice.svg) | [Datei](out/excalidraw/13-inferenz-und-advice.excalidraw) |
| Entwicklung | [Skills, CI und Abnahme](out/svg/14-arbeitsweise-und-ci.svg) | [Datei](out/excalidraw/14-arbeitsweise-und-ci.excalidraw) |
| RC2-Topologie (Zielbild) | [Standort, Hosts, Netze und externer Zugang](out/svg/15-rc2-infrastruktur.svg) | [Datei](out/excalidraw/15-rc2-infrastruktur.excalidraw) |

## Diagramme bearbeiten

Die PlantUML-Dateien in [`src/`](src/) sind die Quellen. Das Skript verwendet
die in [`package.json`](package.json) gepinnte Excaliplant-Version und rendert
SVG, PNG und Excalidraw. Führe es aus dem Repository-Stamm aus.

```sh
docs/diagrams/render.sh
docs/diagrams/render.sh src/03-deploy-und-revisionen.puml
```

Prüfe nach einer Änderung die gerenderten Texte und Pfeile. Checke die
aktualisierte Quelle zusammen mit ihren drei Exporten unter [`out/`](out/) ein.

Die Grafik im [Projekt-README](../../README.md) entsteht aus
[`readme/operations.puml`](readme/operations.puml). Ihre beiden SVG-Varianten
verwenden dieselbe gepinnte Excaliplant-Version und eine kurze Hervorhebung
des Rückwegs zur Beobachtung. Der Browser berücksichtigt die Einstellung
für reduzierte Bewegung.

```sh
npm --prefix docs/diagrams ci --ignore-scripts
node docs/diagrams/render-readme.mjs
```
