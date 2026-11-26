# Karten für Server, Geräte, Steward HA und RC2

Reihenfolge, Budgets und Referenzaufbau stehen im
[Plan nach RC1](../post-rc1.md). Der erste Gerätekatalog fokussiert die
in der Abnahme tatsächlich verfügbaren Profile. Die Flottenverwaltung
und die native Proxmox-HA-Steuerung können unabhängig verwendet werden.

[Linux-, Geräte- und KI-Profile](infrastructure-design/05-linux-devices-and-ai.md) ·
[Dashboard und Topologie](infrastructure-design/06-observability-and-ui.md) ·
[Steward-HA-Vertrag](infrastructure-design/07-steward-ha.md) ·
[Abnahme und Upgrade](infrastructure-design/08-delivery-and-iterations.md)

## IN01 — Eigenständige Linux-Server

**Voraussetzung:** FL03; BK10 für freigegebene Linux-Backups.
**Einstieg:** RC1-Host-Dienste, registrierte Executor-Aktionen, Status,
Anwendungsgraph und Backup-Beobachtungen.

1. Binde einen lokalen Linux-Host und einen externen unterstützten Linux-
   Host über ausgehende Agentenverbindungen an. Melde begrenzte Inventar-,
   Ressourcen- und Dienstbeobachtungen einschließlich Versions- und
   Capability-Angaben. Ein RC1-Host kann zunächst im reinen
   Beobachtungsmodus registriert werden; seine laufenden Anwendungen
   behalten ihren lokalen Zustand. Das Referenzprofil nutzt Ubuntu 26.04
   LTS und prüft Architektur, systemd sowie die vom jeweiligen vServer-
   Anbieter tatsächlich verfügbaren Fähigkeiten.
2. Biete pro Ziel die bereits freigegebenen RC1-Executor-Aktionen und
   Backup-Anforderungen an, soweit Host, Operatorrolle und Richtlinie
   sie erlauben. Der Flottenmodus fügt jedem Aufruf Identität, Zielbindung
   und Auditkorrelation hinzu. Verwende eine explizite Eigentumsübergabe
   für schreibende Verwaltung.
3. Definiere Offline-Status, begrenzten Beobachtungspuffer, Wiederverbindung
   mit Sequenz-/Generationsprüfung sowie Widerruf. Offline-Ziele führen
   lokal verantwortete Abläufe nach ihrer letzten lokalen Policy weiter.

**Check/done**: Zwei echte Linux-Anschlüsse, davon einer über einen
getrennten Netzwerkpfad, mit sichtbarem Dienst, korreliertem Executor-Job und
zugeordnetem Backup-Status. Eine getrennte Verbindung, Rotation und
Wiederaufnahme hinterlassen einen lückenlos erklärbaren Inventarzustand.

## IN02 — Lokale und externe Geräte

**Voraussetzung:** FL01–FL02. **Einstieg:** Inventar- und
Health-Beobachtungsverträge, Netzwerkgrenzen aus FL01.

1. Erfasse explizit registrierte IP-Geräte oder Dienste mit einem festen
   Geräteprofil, Site, stabilem Datensatz, Adresse, Kontakt und
   Datenquelle. Beginne mit TCP/HTTPS-Erreichbarkeit und einem
   Read-only-SNMPv3-Profil für ausgewählte Netzgeräte. Adressänderung
   mit bestätigter Identität erhält die Zuordnung. Agentenlose externe
   Geräte werden über einen freigegebenen Connector im Zielnetz geprüft.
   Für das NAS erfasse Freigaben und beobachte Erreichbarkeit und
   Kapazität über einen registrierten, lesenden Endpunkt oder Connector.
   Fehlende Kapazitätsmessungen erscheinen als unbekannt.
2. Beschränke Protokolle, Zieladressen, Ports, erlaubte SNMP-OIDs,
   Payload-Größen, Intervalle und Egress durch die Registrierung.
   Unterscheide beobachteten Zustand, Verbindungsfehler,
   Berechtigungsfehler und fehlende Messwerte. Verknüpfe manuelle
   Beziehungen wie Switch, VLAN und Standort mit Quelle und Änderungsverlauf.
3. Zeige je Gerät seine tatsächlich unterstützten Aktionen und
   Prüfungen. Das erste Profil konzentriert sich auf Beobachtung
   und betreibergepflegte Verknüpfungen. Gerätespezifische Schreibadapter
   mit eigenem Berechtigungsmodell werden bei konkretem Bedarf priorisiert.

**Check/done**: Mindestens ein reales lokales und ein getrennt
erreichbares Gerät oder registrierter Dienst. Nachweis gültiger
Messwerte und eines Gerätefehlers, fehlgeschlagener
Authentisierung, gesperrter Weiterleitung auf unregistrierte Ziele
sowie eingeschränkter Sichtberechtigung.

## IN03 — Dashboard, Topologie und Quellen

**Voraussetzung:** IN01–IN02, PX02, BK10, PH01.
**Einstieg:** bestehende React-UI, Status-/Audit-API und RC1-
Anwendungsabhängigkeiten.

1. Baue Flottenübersicht und Gast-/Host-/Gerätedetail mit Filtern nach
   Site, Instanz, Typ und Zustand. Verknüpfe PVE-Metriken und
   Host-/Gerätezeitreihen in begrenzten Zeitfenstern, mit Einheiten,
   Beobachtungsquelle und Lücken. Zeige dazu Jobs, Backup-Stand und
   native HA-Platzierung.
2. Implementiere Baum und fokussierbaren Graphen. Kanten unterscheiden
   Beherbergung, Netz, Storage, Backup, Abhängigkeit und HA-Eignung.
   Jede Kante hat Herkunft und Frische. Die API filtert Objekte, Kanten,
   Suchtreffer und aggregierte Zähler nach derselben Berechtigung.
   Aktionen verwenden die FL03-Vorschau und den aktuellen Zielkontext.
3. Ergänze Testdaten für acht PVE-Knoten, zwei externe Linux-Server,
   ein NAS und mindestens 100 Gastobjekte. Teste auch ein Einzelhostprofil
   ohne externe Ziele und eine Flotte mit mehreren PVE-Instanzen ohne HA.
   Prüfe gebündelte Abfragen, paginierte Listen, eine per Tastatur
   bedienbare Detailansicht und einen gleichwertigen Listenpfad für den Graphen.
   Der Browser zeigt ausgefallene Quellen mit ihrem letzten Messzeitpunkt.

**Check/done**: Browser-Abnahme der Flottenübersicht, der Navigation
von Site über Gast zu Storage/Backup und der Darstellung einer
Migration oder Netzstörung. Tests belegen, dass Site-beschränkte Nutzer
fremde Knoten und Beziehungen weder direkt noch über Zählwerte sehen.
Messwerte und Zustände eines repräsentativen Ausschnitts sind gegen
die echten Quellen geprüft.

## CP01 — Replizierter Steuerzustand und Wiederanlauf

**Voraussetzung:** FL03, BK11 und IN03. **Einstieg:** RC1-SQLite-Stores,
FL02-Revisionsverlauf und FL03-Auftragsjournal.

1. Entscheide im ADR zum Quorum-Profil über einen unterstützten
   etcd-3.x-Stand, mTLS, Rechte pro Dienstidentität, Key-Bereiche,
   Größenbudgets und Aufbewahrung. Entwirf das Topologie-Preflight für
   drei stimmberechtigte, physisch getrennte und administrativ aufgenommene
   Mitglieder. Setze voraus, dass sie unabhängig voneinander booten und
   ihren Storage erreichen können.
2. Repliziere den kleinen autoritativen Zustand. Dazu gehören Revisionen,
   Agentenregister und Widerrufe, Befehlsansprüche, Scheduler-Cursor,
   Rollenepochen und referenzierte Ausführungsergebnisse. Schreibpfade
   nutzen zweckgebundene APIs und transaktionale Vorbedingungen. Lokale
   Executor-Datenbanken, Logs und Messreihen bleiben in ihren
   Vertrauensdomänen. Geheime Werte und Backup-Blöcke bleiben in ihren
   jeweiligen Speicherpfaden. Passive Replikate verfolgen bestätigte
   Revisionen und synchronisieren nach einer Beobachtungslücke von einem
   aktuellen Snapshot.
3. Implementiere einen überprüfbaren Import von der einzelnen
   Flotteninstanz mit gestoppten Schreibern, abgeglichenen Jobs und
   eindeutigem Eigentumswechsel. Erzeuge verschlüsselte, extern geprüfte
   Steuerzustands-Snapshots. Der Wiederanlauf nach Totalausfall beginnt
   isoliert mit einer neuen Steuerungs-Generation. Alte Executor-
   Autorisierungen werden widerrufen oder stillgelegt; Zielzustand und
   native Tasks werden vor der neuen Schreibfreigabe abgeglichen. Snapshot,
   Schlüssel und Startanleitung bleiben außerhalb des ausgefallenen Verbunds
   abrufbar.

**Check/done**: Test mit drei Mitgliedern belegt Erhalt bestätigter
Revisionen und Befehlsansprüche bei Einzelausfall, Sperre neuer
Claims bei Quorumverlust und Konfliktprüfung bei parallelen Änderungen.
Import ist nach unterbrochenem Versuch wiederholbar. Ein Restore in
neuer Generation weist alte Autorisierungen ab und bietet die Daten
des letzten geprüften Snapshots an.
[etcd-API](https://etcd.io/docs/v3.6/learning/api/) ·
[etcd-Wiederherstellung](https://etcd.io/docs/v3.6/op-guide/recovery/)

## CP02 — Rollenwahl, Schreibsperren und Job-Übernahme

**Voraussetzung:** CP01. **Einstieg:** FL03-Journal, PX03-
Task-Abstimmung und zielgebundene Executor-Credentials.

1. Vergib atomar eine zeitlich begrenzte Rolle mit monotoner Epoche
   innerhalb der Steuerungs-Generation. Der Ausführungspfad prüft
   aktuelle Generation, Rolle und Epoche per konsistenter Abfrage.
   Vor jedem externen Schreibaufruf beansprucht er den Auftrag und
   dessen Ressourcensperre transaktional und protokolliert den
   Übergang zu `dispatching`. Der Sperrbereich entspricht der Wirkung,
   etwa Gast und geplanter Zielknoten bei einer Relocation. Ohne
   Quorum-Bestätigung entsteht kein neuer Dispatch. Eine
   Zuweisungs-Lease erlischt. Ein vorher bestätigter Dispatch behält seine
   Sperre und kann am nativen Ziel noch wirksam werden.
2. Begrenze native Schreibcredentials auf den zielgebundenen
   Executor. Die Steward-Lease wird von PVE nicht durchgesetzt;
   zwischen letzter Prüfung und API-Aufruf besteht ein Ausfallfenster.
   Bei einem unklaren Dispatch wird der verbundweite Sperreintrag auch
   bei einem Agentenwechsel übernommen. Eine neue Ausführung auf
   derselben Ressource setzt den belegten Abschluss des alten
   Dispatchs voraus. Falls dieser nicht belegbar ist, muss der alte
   Schreibpfad nachweislich beendet oder gesperrt und der native
   Zustand einschließlich möglicher Tasks abgeglichen werden.
   Bei fehlender Evidenz bleibt der Auftrag für den Operator gesperrt.
   Reguläre, voneinander unabhängige Ziele bleiben bedienbar.
3. Übernimm ausstehende Jobs ohne bestehenden Dispatch-Claim anhand von
   Revision und Freigabe. Ein bereits beanspruchter Job geht in den
   Abgleich und wird nicht erneut abgesendet. Der neue Rolleninhaber
   verfolgt bekannte native Tasks anhand ihrer UPID und prüft danach den
   tatsächlich beobachteten Zielzustand.
   Für eine verlorene Antwort sind Gastgeneration, PVE-Tasks,
   Executor-Journal und erreichter Zielzustand die Abgleichsdaten.
   Status, Schreibsperre, Grund und sicherer nächster Schritt erscheinen
   im Audit und in der Bedienoberfläche.

**Check/done**: Zwei konkurrierende Scheduler, alter Prozess nach
Lease-Verlust, pausierter Agent direkt vor dem PVE-Aufruf, verlorene
API-Antwort, verlorenes Quorum und Wiederkehr. Der Realtest belegt höchstens
einen nativen Auftrag je freigegebenem Versuch, keine kollidierende zweite
Aktion trotz Wiederanlauf des alten Senders und fortgesetzte Bedienung
unabhängiger Ziele. Eine hängende Aktion bleibt sichtbar gesperrt, wenn
die erforderliche Ausführungsevidenz fehlt.

## CP03 — Dynamische Dienstplatzierung und Hot-Standbys

**Voraussetzung:** CP02, IN03. **Einstieg:** Wartungsfenster,
Job- und Dienstezustände, persistenter Scheduler-Cursor.

1. Definiere ein Rollenprofil für den Flottenkoordinator/Scheduler und
   als zweite freigegebene Rolle die Backup-Planung. Pro Rolle bestimmt
   die Policy Eignung, Mindestkapazität, Versionsfenster, Ausfalldomäne,
   einen aktiven Slot und ein bis zwei Standbys. Bei knappen Ressourcen
   bleibt die gewünschte Redundanz als Abweichung sichtbar. Ziehe
   deklarierte Reserven für andere Workloads vom Platzierungsbudget ab,
   etwa den RAM für den geplanten KI-Container. Laufende PVE-/Restic-
   Datentransfers folgen ihren Backend- und Job-Verträgen.
2. Platziere Rollen nach den Regeln im [Referenzplan](../post-rc1.md).
   Rüste Standbys mit vorbereiteten Prozessen, geprüftem Datenstand
   und eigenem Readiness-Status aus. Eine Übernahme erfordert aktuelle
   State-Revision, Mehrheitsbestätigung und den CP02-Schreibpfad.
   Ein privater redundanter Zugangspfad routet Agenten und zugelassene
   Benutzer zu verfügbaren Endpunkten; die Endpunkte prüfen die
   Autorität auch nach einer Rollenumschaltung. Stelle Replikationsalter,
   gewählten Knoten und Ausschlussgründe in der UI dar.
3. Unterstütze geplantes Drain, automatisches Failover und Wiederaufnahme
   eines zurückkehrenden Hosts als Kandidat. Das gewünschte und aktuelle
   Rollenregister bleiben sichtbar. Beschränke Versionen auf ein
   verifiziertes Kompatibilitätsfenster für rollende Upgrades und übergib
   Rollen kontrolliert bei Schemainkompatibilität. Rechenintensive
   Scanner, Builder und KI erhalten erst mit eigenen Rollenverträgen
   eine dynamische Platzierung.

**Check/done**: Auf drei getrennten Rechnern ein und zwei vorbereitete
Ersatzinstanzen testen, aktive Instanzen einzeln ausfallen lassen und
jeweils Übernahme, Endpunkt-Erreichbarkeit, laufende Jobs und
Wiederanlaufzeit belegen. Beim Verlust der Mehrheit gibt es keine neue
Schreibrolle. Eine zurückkehrende Instanz wird Standby oder bleibt
mit sichtbarem Grund ausgeschlossen. Ein Kandidat mit zu wenig RAM nach
Abzug einer Reserve wird mit Begründung übersprungen. Die Backup-Planung
startet je Zeitfenster und Ressource höchstens einmal.

## IR01 — Integrierte Abnahme der Referenzflotte

**Voraussetzung:** M9–M14, freigegebene Referenzgeräte, Testgäste und unabhängige
Wiederherstellungsziele. **Einstieg:** Gates PX01, BK11, PH03, IN03, CP03.

1. Erzeuge die Referenzkonfiguration mit drei PVE-Clusterknoten,
   fünf einzeln registrierten PVE-Hosts, lokalem NAS und zwei externen
   Ubuntu-26.04-LTS-Hosts. Verknüpfe lokale und unabhängige
   PBS-/Restic-Ziele nach ihrer tatsächlichen Rolle. Prüfe Hostzuordnung
   und RAM-Reserve für einen Beispielcontainer auf dem leistungsstarken
   Einzelhost. Vergleiche die auf der Karte beobachtete Topologie mit
   dem echten Aufbau. Hardwareäquivalente Hosts sind für die Abnahme
   zulässig, sofern dieselben Fähigkeiten und Ausfalldomänen geprüft werden.
2. Führe den End-to-End-Durchlauf als zusammengefasste Abnahme aus.
   Enthalten sind Richtlinienübernahme, Gastanlage, geplanter Backup-Lauf,
   Nutzdaten-Restore, PVE-Gast-Failover und Steward-Rollenwechsel.
   Prüfe jeweils korrekte Zuständigkeit, Verhalten bei Quorumverlust,
   Wiederaufnahme und RPO/RTO. Prüfe einzeln den NAS-Ausfall und einen
   WAN-Abbruch. Die Oberfläche zeigt die betroffenen Freigaben, externen
   Hosts und Backup-Kopien. Unabhängige lokale Pfade bleiben bedienbar.
3. Stelle bei simuliertem vollständigem Verlust der Steuerung einen
   unabhängigen Steuerzustands-Snapshot wieder her. Schließe Zielabgleich,
   abgesicherte Neuregistrierung alter Agenten und fortgesetzte Bedienung
   mit ein. Halte Topologie, Versionen, Gate-Ergebnisse und gemessene
   Zeiten reproduzierbar fest.

**Check/done**: Alle Rollen des gemischten Referenzprofils bestehen die
kombinierten Gates auf dem geprüften Commit. Der Ausfall eines PVE-Hosts,
der Verlust einer Steward-Rolle und der Verlust des gesamten
Steward-Steuerzustands sind separat messbar. Kein ungewisser Job wird
erneut abgesendet.

## IR02 — Signiertes RC2, Upgrade und Support-Matrix

**Voraussetzung:** IR01, S01-Signaturkette. **Einstieg:** bestehender
Release- und Provenienzpfad, PX01-Pakete und CP01/CP03-Upgrade.

1. Führe das Upgrade eines bestehenden RC1-Einzelhosts und die explizite
   Aufnahme in eine Flotte durch. Prüfe erhaltene Projekte, lokale
   Sicherheitsgrenzen, Daten, Konfigurationsrevisionen und deaktivierte
   Fähigkeiten. Prüfe den Rückkehrpfad für fehlgeschlagenes Upgrade
   und aktivierte Flottenverwaltung.
2. Prüfe das signierte Bundle für den nativen PVE-Host und das
   Flotten-/Quorum-Profil. Liefere SBOM, Provenienz, Versionsmatrix,
   Unterstützungsgrenzen, Installations-/Rückbauanleitung und Verfahren
   für externe Restores. Die Matrix nennt PVE/PBS-/Linux-Versionen,
   Host-/Gasttypen, Storage- und Geräteprofile sowie das geprüfte
   Ausfallmodell.

**Check/done**: Saubere Installation, Upgrade aus RC1, zweite Anwendung
ohne Änderungen und validierte Rückkehr auf dem dafür freigegebenen
Testprofil. Signierte Pakete, alle für RC2 freigegebenen Gates und
die tatsächlich unterstützten Fähigkeiten sind in Release und
`STATUS.md` verknüpft.
