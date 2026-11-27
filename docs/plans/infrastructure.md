# Karten für Server, Geräte, Steward HA und RC2

Reihenfolge, Budgets und Referenzaufbau stehen im
[Plan nach RC1](../post-rc1.md). Der erste Gerätekatalog fokussiert die
in der Abnahme tatsächlich verfügbaren Profile. Die Flottenverwaltung
und die native Proxmox-HA-Steuerung können unabhängig verwendet werden.

[Linux-, Geräte- und KI-Profile](infrastructure-design/05-linux-devices-and-ai.md) ·
[Dashboard und Topologie](infrastructure-design/06-observability-and-ui.md) ·
[RC2-Bedienkonzept](rc2-webapp.md) ·
[Steward-HA-Vertrag](infrastructure-design/07-steward-ha.md) ·
[Abnahme und Upgrade](infrastructure-design/08-delivery-and-iterations.md)

## UI01 — Bedienbasis und Vollständigkeit

**Voraussetzung:** PX02 für die lokale Ansicht, FL01–FL02 für Flotte und
Vererbung, FL03 für Flottenaufträge.

1. Fixiere die bestehenden Bedienwege für Anmeldung, Suche, Zielwechsel,
   Konfiguration und Auftragsverfolgung mit Browser-Regressionstests.
   Unterscheide abgelaufene Sitzung, API-Ausfall und fehlende Rechte.
   Zielgebundene Abfragen verwerfen verspätete Ergebnisse. Entwurf,
   Revision und Auftragsstatus bleiben bei Polling, Reload und
   konkurrierender Bearbeitung nachvollziehbar. M9 verwendet dieselbe
   Grundlage im lokalen PVE-Profil.
2. Liefere Betrieb, Dienste, Inventar, Topologie und Änderungen mit
   stabilem Flotten-, Standort- und Maschinenkontext. Unter **Betrieb**
   stehen Störungen und anstehende Entscheidungen vor den Kennzahlen.
   Jeder Vorgang zeigt Ziel, Auswirkung, beobachteten Zustand und den
   direkten Einstieg zur Prüfung oder Entscheidung. Den gleichen Vorgang
   finden berechtigte Betreiber in der Flotte und bei den betroffenen
   Maschinen. Die separate
   **Configuration** bündelt Zugriffsmethoden und Rollen, Zorec/KI,
   Funktionsfreigaben, Integrationen, Schutz und Richtlinien.
   Der Katalog ordnet jede freigegebene Funktion und darstellbare
   Einstellung aus API, CLI oder Schema einer Oberfläche zu. Er gibt
   Berechtigung, Voraussetzungen, wirksamen Wert, Herkunft und
   Bearbeitbarkeit an. Geheime Werte erscheinen als Referenzen.
   System, Hell und Dunkel gelten für Navigation, Anmeldung, Karte und
   Zorec. Neue Adapter und Funktionen erweitern den Katalog.
   Die Systemübersicht bündelt die Fachbereiche und führt mit demselben
   Geltungsbereich zu Tabellen, Fachansichten und gemeinsamer Topologie.
   Farbschema per Symbol, Systemeinstellung und Navigation funktionieren
   mit Maus, Tastatur und Touch. Breite Datendarstellungen haben einen
   eigenen horizontalen Scrollbereich.
3. Zeige Zorec im Betrieb und öffne seinen kontextbezogenen Chat aus
   Ressourcen, Befunden, Aufträgen und der Diensteinrichtung. Manuelle
   Einrichtung und geführte Vorschläge verwenden denselben Entwurf.
   Typisierte Zustände steuern die vorhandenen 14 Gesten und drei
   zusätzliche Zustände für Freigabe, Ausführung und nachgewiesene
   Wiederherstellung. Eine Textanzeige trägt die Bedeutung unabhängig
   vom Bild und von optionaler KI. Zorec verlinkt Beobachtung, Policy,
   Auftrag und Prüfung.
   Prüfe getrennte Shells für Admin Lesen, Admin Edit und Berichte.
   Der Chat bietet Admin Edit als bewusste Auswahl gemäß wirksamem
   Berechtigungsprofil an. API-Chat, registrierte Aktionen und
   Credential-Nutzung folgen dem gemeinsamen
   [Zorec-Vertrag](rc2-webapp.md#zorec-shells-und-berechtigungen).

**Check/done**: Produktionsbuild und Browserprüfungen mit echten
API-Fixtures für beide Farbschemata, Tastatur, Rechte, Offlinezustand,
veraltete Antworten und konkurrierende Entwürfe. Die freigegebenen
Funktionen des getesteten Profils sind im Katalog auffindbar. Ein
Zielwechsel zeigt ausschließlich Werte und Aktionen des neuen Ziels.
Im Betrieb verfolgt der Betreiber eine Störung mit automatischer
Nachprüfung und öffnet eine fällige Entscheidung mit Änderungsvorschau.
Beide Vorgänge sind im passenden Maschinenkontext und in der Flotte
auffindbar.
Die Browserabnahme wechselt von der Systemübersicht zum fokussierten
Objekt und zur Gesamttopologie, in der sich alle Ebenen gemeinsam und
einzeln anzeigen lassen. Jede sichtbare Aktion liefert ein überprüfbares
Ergebnis oder zeigt ihre Voraussetzung bzw. Verfügbarkeit.

## IN01 — Eigenständige Linux-Server

**Voraussetzung:** FL03. BK10 qualifiziert den separaten
Sicherungs-Schreibpfad in M12.
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
2. Verwende für das erste Containerprofil rootless Podman und Quadlet.
   Biete Inventar, Anlage aus einem zugelassenen Dienstprofil, Start,
   Stopp und Neustart mit denselben Bedienwegen wie bei PVE-LXC. Zeige
   Image, Ressourcenlimits, Speicher, Portzuordnung und Netzwerk je
   Capability. Der lokale Executor vermittelt registrierte Aktionen.
   Vorhandene Container wechseln erst nach bestätigter Übernahme in die
   schreibende Verwaltung. Debian, Fedora und Arch verwenden denselben
   Adaptervertrag und erhalten getrennte Profilabnahmen.
3. Definiere Offline-Status, begrenzten Beobachtungspuffer, Wiederverbindung
   mit Sequenz-/Generationsprüfung sowie Widerruf. Offline-Ziele führen
   lokal verantwortete Abläufe nach ihrer letzten lokalen Policy weiter.

**Check/done**: Zwei echte Linux-Anschlüsse, davon einer über einen
getrennten Netzwerkpfad. Auf dem Ubuntu-Referenzhost einen zugelassenen
Container anlegen, starten, stoppen und neu starten. Ergebnis, Health
und Executor-Job sind in derselben Ansicht verknüpft. Vorhandene
Sicherungsbeobachtungen oder die Deckungslücke sind sichtbar. Trennung,
Rotation und Wiederaufnahme bleiben im Inventar nachvollziehbar.

## IN02 — Lokale und externe Geräte

**Voraussetzung:** FL01–FL02. **Einstieg:** Inventar- und
Health-Beobachtungsverträge, Netzwerkgrenzen aus FL01.

1. Registriere ein UniFi Cloud Gateway und einen verwalteten Switch mit
   ausgewiesenem Modell, Firmware, Network-Version und Lesezugang zur
   dokumentierten API. Übernimm Standorte, verwaltete Geräte und
   beobachtete Clients, VLAN-Zuordnung, Uplinks, Portwerte und verfügbare
   Regelinformationen. Ausgehandelte Linkrate, Verkehrsmessung und
   konfigurierte Kapazität sind eigene Werte. Felder ohne belegte Quelle
   erscheinen als unbekannt. Ein beobachteter Client erhält einen
   Inventareintrag. Seine Übernahme als verwaltetes Ziel braucht eine
   bestätigte Identität und ausdrückliche Registrierung.
2. Ergänze explizit registrierte Geräte, NAS-Freigaben und Dienste über
   einen Connector im Zielnetz. Verwende begrenzte TCP-/HTTPS-Prüfungen
   und bei Bedarf lesendes SNMPv3. Manuell bestätigte Kabel- und
   VLAN-Zuordnungen behalten Herkunft und Änderungsverlauf. Prüfe
   konkrete Erreichbarkeit mit Quelle, Ziel, Richtung, Protokoll und
   Zeitpunkt. Beschränke Protokolle, Ziele, Abfragegröße und Intervalle
   auf den registrierten Bereich.
3. Zeige Authentisierungsfehler, Ausfall, fehlende Daten und tatsächlich
   unterstützte Funktionen. NX04 verwendet dieses Inventar später
   für Vorschau und Readback einer Netzänderung.

**Check/done**: Reales UniFi Cloud Gateway mit Switch und mindestens
einem tatsächlich beobachteten Client. Die Karte gleicht Port und
VLAN gegen UniFi ab und zeigt eine belegte Dienstprüfung. Ein lokales
NAS oder Gerät und ein getrennt erreichbarer Dienst sind sichtbar.
Fehlgeschlagene Authentisierung, nicht registrierte Weiterleitung und
eingeschränkte Sichtberechtigung werden geprüft.

## IN03 — Dashboard, Topologie und Quellen

**Voraussetzung:** UI01, IN01–IN02, PX02. BK10 und PH01 liefern spätere
Sicherungs- und HA-Beobachtungen für dasselbe Modell.
**Einstieg:** bestehende React-UI, Status-/Audit-API und RC1-
Anwendungsabhängigkeiten.

IN03 übernimmt Navigation, Zielauswahl, Farbschema und Zorec aus UI01
und dem [RC2-Bedienkonzept](rc2-webapp.md). Fehlt ein optionaler
Adapter, zeigt die Ansicht die belegte Abdeckung und stellt Funktionen
mit erfüllten Voraussetzungen weiter bereit.

1. Baue Flottenübersicht und Gast-/Host-/Gerätedetail mit Filtern nach
   Site, Instanz, Typ und Zustand. Verknüpfe PVE-Metriken und
   Host-/Gerätezeitreihen in begrenzten Zeitfenstern, mit Einheiten,
   Beobachtungsquelle und Lücken. Zeige CPU, RAM und Storage als
   Kapazität, Belegung und Reservierung sowie GPU/PCI, USB, HDMI,
   Netzports und Freigaben als beobachtete oder dokumentierte
   Zuordnungen. Identische physische Geräte und Speicherpools zählen
   je Flotte einmal. Lokale Hardwarebindung bleibt am Gast sichtbar.
2. Implementiere Baum, Listen und die Platzierung von Diensten in Hosts
   und Standorten. Die Ebenen für Verkabelung, Netzregeln und Zugang
   sind schaltbar. Erzeuge PlantUML aus der autorisierten Live-Projektion
   und rendere mit Excaliplant. Hook-IDs verbinden Hover, Klick und
   Tastatur mit der Ressource oder Kante. Der Graph hält
   Beherbergung, Gerätebindung, VLAN-Zuordnung, Regel, Tunnel und
   bestätigten Prüfpfad auseinander. Die API filtert Objekte, Kanten,
   Suchtreffer und Zähler vor der Darstellung. Das Detailpanel startet
   eine FL03-Vorschau für tatsächlich freigegebene Aktionen. Eine
   IPv4- oder Verbindungsänderung in der Vorschau rendert den geplanten
   Zustand aus dem Entwurf. Der bestätigte Istzustand folgt aus dem Readback.
3. Ergänze Testdaten für acht PVE-Knoten, zwei externe Linux-Server,
   ein NAS und mindestens 100 Gastobjekte. Teste auch ein Einzelhostprofil
   ohne externe Ziele und eine Flotte mit mehreren PVE-Instanzen ohne HA.
   Prüfe gebündelte Abfragen, paginierte Listen, eine per Tastatur
   bedienbare Detailansicht und einen gleichwertigen Listenpfad für den Graphen.
   Der Browser zeigt ausgefallene Quellen mit ihrem letzten Messzeitpunkt.

**Check/done**: Im Browser aus der globalen Suche zu PVE-Gast und
Linux-Container navigieren. Die Live-Karte zeigt Core-Dienstplatzierung,
Hostbindung, einen Switchport mit belegter Linkrate, VLAN und einen
konkreten Netztest. Knoten und Kanten lassen sich per Hook auswählen.
Eine überprüfbare Vorschau wird nach einer Änderung neu gerendert.
Mindestens eine reale Gerätebindung ist gegen das native Inventar
geprüft. Offlinequelle, ausstehende Schutzdaten, Zielwechsel,
Rollenfilter und Listenpfad funktionieren auch ohne freigegebenen
Backup- oder HA-Adapter. Zorec erklärt einen belegten Vorgang ohne KI.

## NX01 — Identität, DNS, Zertifikate und Zeit

**Voraussetzung:** FL01–FL03, IN03. **Einstieg:** autorisierte
Flottenidentität, bestehende Session-Regeln und Stewards Bootstrap-Zugang.

1. Definiere sichtbare Zuständigkeit je Benutzer, Gruppe, Hostidentität,
   DNS-Zone, Zertifikat und Zeitquelle. Binde für das Referenzprofil ein
   selbstgehostetes IPA-Verzeichnis mit interner DNS-Zone und interner
   CA an. FreeIPA ist der erste Kandidat. Web-Logins nutzen einen
   angebundenen OIDC-Anbieter mit Gruppenabbildung. Die Zeitrolle nutzt
   eine konfigurierte NTP-Quelle, beispielsweise mit chrony. Öffentliche
   Zertifikate folgen dem freigegebenen ACME-Profil.
2. Zeige im Flotten- und Zielkontext wirksame Rolle, Zone, Zertifikatskette
   und Ablauf, Quelle der Zeit und Synchronisationszustand. Der
   zuständige Adapter vergibt und widerruft Identitäten, DNS-Einträge
   und Zertifikate innerhalb zugeteilter Bereiche. Zentrale Rollen
   erhalten nur die für ihren Auftrag nötigen Referenzen und melden
   Erneuerung, Drift und Ausfall in den gemeinsamen Verlauf.
3. Prüfe die Startreihenfolge für Verwaltung, lokalen Resolver,
   Zeitsynchronisation, Verzeichnis und zentrale Dienste. Halte einen
   privaten Wiederanlaufzugang mit eigener Bootstrap-Identität
   verfügbar, wenn der verwaltete Identitäts-, DNS- oder Zeitdienst
   ausfällt. Ein ausfallender Dienst darf weder einen neuen Login noch
   eine Veröffentlichung fälschlich als erfolgreich markieren.

**Check/done**: Eine reale Gruppe und ein Host werden korrekt
zugeordnet. Ein Testdienst erhält einen Eintrag im delegierten DNS
und eine verifizierte Zertifikatskette. Erneuerung, entzogener Zugriff,
Zeitabweichung sowie Wiederanlauf bei vorübergehend ausgefallenem
Basisdienst sind im Auftragsverlauf belegt.

## NX02 — Verwalteter VPN-Verbund und HTTPS-Veröffentlichung

**Voraussetzung:** NX01, IN01. **Einstieg:** ausgehende Agentenaufnahme,
FL03-Aufträge und Netzwerkprojektion aus IN02–IN03.

1. Biete **VPN-Host**, **VPN-Teilnehmer** und **HTTPS-Proxy** als
   unabhängig aktivierbare Rollen mit Host-Eignung, Reservierung und
   verantwortlicher Instanz. Nach einmaliger bestätigter Aufnahme
   richtet der registrierte Host-Executor einen WireGuard-Tunnel
   zwischen freigegebenen Zielen ein. Bindung, freigegebene Routen,
   Schlüsselrotation und Widerruf werden im gemeinsamen Auftrag geführt.
   Agentenaufnahme und privater Wiederanlauf bleiben vor dem Tunnel
   erreichbar. Management, Standortverkehr und veröffentlichte Dienste
   haben getrennte Pfade und Rechte.
2. Veröffentliche auf einem externen Linux-Host genau einen registrierten
   Webdienst pro bestätigtem Routenauftrag. Der Auftrag prüft
   Zielidentität, Route, DNS, TLS sowie den externen HTTPS-Abruf.
   Reservierte Ressourcen, Teilanwendung, Rücknahme und beobachtete
   Erreichbarkeit erscheinen gemeinsam in Karte und Verlauf. Eine
   gewünschte Route erscheint bis zum positiven externen Check als
   ausstehend oder ungeprüft.
3. Behandle doppelte oder überlappende Netzzuordnungen, widerrufene
   Teilnehmer und Teilfehler mit sichtbarem Abgleich. Ein widerrufenes
   Ziel verliert Route und zugehörige Freigaben. Die Wiederaufnahme
   prüft Identität und aktuelle Revision erneut.

**Check/done**: Ein freigegebener interner und ein externer Server bauen
den Tunnel nach Aufnahme automatisch auf. Der externe HTTPS-Test folgt
über die beabsichtigte Route zum registrierten Dienst. Rotation,
Widerruf und Tunnelausfall sind einschließlich erreichbarem privatem
Verwaltungsweg geprüft.

## NX03 — Externes Portal für SSH und Gast-Desktops

**Voraussetzung:** NX01–NX02. **Einstieg:** bestätigte
Veröffentlichungs- und Sitzungsgrenzen des externen Hosts.

1. Aktiviere das Zugangsportal als eigene Rolle mit separatem
   Webendpunkt, Login, MFA und Sitzungsbereich. Ein vorhandener
   OIDC-Anbieter kann Nutzer und Gruppen zuordnen. Der Sitzungsfluss
   wird separat von der Zielautorisierung qualifiziert. Portalrechte
   sind an registrierte Zielressource, Protokoll und Gültigkeit gebunden.
   Der normale öffentliche Web-Proxy und der private Adminzugang
   behalten eigene Berechtigungs- und Netzgrenzen.
2. Vermittle eine geschützte Website, SSH und eine grafische
   Gast-Sitzung über den verifizierten Tunnel. Für SSH und RDP oder
   VNC ist Guacamole ein Kandidat. Die konkrete Integration muss
   Sitzungs- und Zielrechte unabhängig durchsetzen. Gast-SSH,
   Gast-Desktop und die native PVE-Konsole sind eigene Funktionen.
   Sitzungen und ihr Widerruf sind im Dienst- und Auftragsverlauf
   sichtbar. [Guacamole-Anmeldung](https://guacamole.apache.org/doc/gug/openid-auth.html)

**Check/done**: Nach getrenntem Login eine geschützte Website und je
eine reale SSH- und Desktop-Sitzung öffnen. Ein Benutzer ohne
Zielrecht erhält weder Verbindung noch Zielmetadaten. Entzogenes
Recht, ablaufende Sitzung und unterbrochener Tunnel sperren den
betroffenen Zugriff. Der private Adminzugang bleibt erreichbar.

## NX04 — Versionierte UniFi-Netzänderungen

**Voraussetzung:** IN02–IN03 und FL03. **Einstieg:** freigegebenes
Cloud-Gateway-/Switchprofil und exakt geprüfte API-Schreibfunktion.

1. Öffne aus einer Netzregel, einem VLAN oder Port einen typisierten
   Entwurf mit aktuellem und gewünschtem Wert, Zielrevision und
   Auswirkungen auf Dienste und Verwaltung. Die UI nennt pro Objekt
   die unterstützten Schreibaktionen. Für Firmware und Rolle ohne
   geprüfte Aktion bleibt die Lesesicht verfügbar. Physische Kabel
   werden vor Ort geändert und in der Karte dokumentiert.
2. Qualifiziere auf dem Referenzprofil eine reversible VLAN- oder
   Firewall-/ACL-Änderung. Führe sie mit getrenntem Schreibrecht über
   registrierte Aktionen aus. Binde Freigabe und Rückweg an dieselbe
   Revision. Prüfe nativen Readback, betroffene Netzpfade und den
   Verwaltungszugang. Nicht bestätigter Vollzug bleibt zum Abgleich
   offen, bis der tatsächliche Zustand belegt ist.

**Check/done**: Ein reales Testnetz durchläuft Vorschau, freigegebene
Änderung, bestätigten Istzustand und Rücknahme. Ein veralteter Entwurf
und ein nicht erlaubtes Netzwerkziel werden abgewiesen. Beobachtung,
Policy und Prüfung bleiben vor und nach der Änderung unterscheidbar.

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

**Voraussetzung:** CP02, IN03. NX01–NX03 liefern die Metadaten für
die Basis- und Zugangsrollen. **Einstieg:** Wartungsfenster,
Job- und Dienstezustände, persistenter Scheduler-Cursor.

1. Definiere ein gemeinsames Rollenprofil für aktive Instanzen,
   Standbys und geplante Reserven. Qualifiziere Flottenkoordinator,
   Backup-Planung und einen standortlokalen zustandsarmen Geräte-
   Connector aus IN02. Die Policy prüft Kapazität, Version,
   Ausfalldomäne, Gerätebindung und Dienstabhängigkeiten. Eine Rolle
   belegt ihren aktiven Slot genau einmal. Hostreserven und geplante
   Standbys werden vor der Platzierung berücksichtigt. VPN-, Proxy-,
   Portal- und Basisrollen übernehmen das Platzierungsmodell und
   führen ihre eigene Eignung sowie den vorgesehenen Wiederanlaufpfad.
2. Platziere Rollen nach den Regeln im [Referenzplan](../post-rc1.md).
   Rüste Standbys mit vorbereiteten Prozessen, geprüftem Datenstand
   und eigenem Readiness-Status aus. Eine Übernahme erfordert aktuelle
   State-Revision, Mehrheitsbestätigung und den CP02-Schreibpfad.
   Ein privater redundanter Zugangspfad routet Agenten und zugelassene
   Benutzer zu verfügbaren Endpunkten; die Endpunkte prüfen die
   Autorität auch nach einer Rollenumschaltung. Stelle Replikationsalter,
   gewählten Knoten und Ausschlussgründe in der UI dar. Der
   Geräte-Connector setzt seine Beobachtung nach dem Wechsel mit
   nachvollziehbarer Quelle und Frische fort.
3. Unterstütze geplantes Drain, automatisches Failover und Wiederaufnahme
   eines zurückkehrenden Hosts als Kandidat. Das gewünschte und aktuelle
   Rollenregister bleiben sichtbar. Nach Verlust eines Replikats ergänzt
   die Platzierung den Sollbestand auf einem geeigneten Host. Die
   Schreibautorität und Quorummitgliedschaft folgen ihren eigenen
   CP01-/CP02-Freigaben. Beschränke Versionen auf ein
   verifiziertes Kompatibilitätsfenster für rollende Upgrades und übergib
   Rollen kontrolliert bei Schemainkompatibilität. Rechenintensive
   Scanner, Builder und KI sowie standortübergreifender Edge-Failover
   erhalten mit eigenen Rollenverträgen eine dynamische Platzierung.

**Check/done**: Auf drei getrennten Rechnern ein und zwei vorbereitete
Ersatzinstanzen testen, aktive Instanzen einzeln ausfallen lassen und
jeweils Übernahme, Endpunkt-Erreichbarkeit, laufende Jobs und
Wiederanlaufzeit belegen. Beim Verlust der Mehrheit gibt es keine neue
Schreibrolle. Eine zurückkehrende Instanz wird Standby oder bleibt
mit sichtbarem Grund ausgeschlossen. Ein Kandidat mit zu wenig RAM nach
Abzug einer Reserve wird mit Begründung übersprungen. Dieselbe
Ressource und Rolle werden nur einmal aktiv gezählt. Die Backup-Planung
startet je Zeitfenster und Ressource höchstens einmal. Beim Ausfall
des Geräte-Connectors bleibt der beobachtete Netzpfad erklärbar.

## IR01 — Integrierte Abnahme der Referenzflotte

**Voraussetzung:** M9–M14, freigegebene Referenzgeräte, Testgäste und
unabhängige Wiederherstellungsziele. **Einstieg:** PX01–PX04,
UI01, IN01–IN03, NX01–NX04, BK11, PH03 und CP03.

1. Erzeuge die [Referenzkonfiguration](../post-rc1.md#referenzaufbau-mit-lokalen-und-externen-systemen)
   aus PVE-Cluster, Einzelhosts, internem Podman-Teilnehmer, zwei
   externen Ubuntu-Hosts, UniFi und NAS. Ordne externer Veröffentlichung,
   Administration, Beobachtung und unabhängiger Kopie ihre Zuständigkeit
   und ihre jeweilige Ausfalldomäne zu. Prüfe reale Topologie,
   Hardwarezuordnung und RAM-Reserve. Hardwareäquivalente Hosts sind
   bei gleichen Fähigkeiten und Ausfalldomänen zulässig.
2. Führe die zusammenhängenden Abläufe im Produktionsbuild aus.
   - **Betrieb:** PVE-Gast und Podman-Container über denselben
     Bedienpfad anlegen und steuern. Von der Flotte zu Maschine,
     Hardware, Switch und beobachtetem Dienstpfad wechseln. Einen
     kontrolliert gestörten Dienst gemäß Policy automatisch
     wiederherstellen. Zorec zeigt Beobachtung, Freigabe, Ausführung
     und verifizierten Zustand auch bei ausgeschalteter KI.
   - **Verbund:** Externen Host aufnehmen und den Tunnel automatisch
     einrichten. Registrierten Dienst über DNS, TLS und HTTPS
     veröffentlichen und extern prüfen. Separat via Portal eine
     geschützte Website, SSH und einen Gast-Desktop erreichen.
     Reversible UniFi-Änderung mit
     geprüftem Rückweg ausführen. Entzogene Zielrechte, WAN-/Tunnel-
     Ausfall und verbleibenden privaten Verwaltungsweg beobachten.
   - **Wiederanlauf:** Geplanter Backup-Lauf und unabhängiger
     Nutzdaten-Restore, PVE-Gast-Failover und Steward-Rollenwechsel.
     Zustand bei Quorum- und NAS-Verlust, Wiederaufnahme, RPO und RTO
     getrennt messen. Lokale unabhängige Pfade bleiben bedienbar.
3. Stelle bei simuliertem vollständigem Verlust der Steuerung einen
   unabhängigen Steuerzustands-Snapshot wieder her. Schließe Zielabgleich,
   abgesicherte Neuregistrierung alter Agenten und fortgesetzte Bedienung
   mit ein. Halte Topologie, Versionen, Gate-Ergebnisse und gemessene
   Zeiten reproduzierbar fest.

**Check/done**: Alle drei Abläufe bestehen auf dem geprüften Commit
mit realen Quellen und verifiziertem Istzustand. Der Ausfall eines
PVE-Hosts, der Verlust einer Steward-Rolle und der Verlust des
Steuerzustands sind separat messbar. Ein ungewisser Job bleibt bis
zum Zielabgleich gesperrt. Die Oberfläche und die Support-Matrix
stimmen je Objekt und Capability mit der Abnahme überein.

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
   Host-/Gasttypen, Storage- und Geräteprofile, UniFi-Modell und
   Firmware, geprüfte Schreiboperation, Portalprotokolle und Basisdienste
   sowie das nachgewiesene Ausfallmodell.

**Check/done**: Saubere Installation, Upgrade aus RC1, zweite Anwendung
ohne Änderungen und validierte Rückkehr auf dem dafür freigegebenen
Testprofil. Signierte Pakete, alle für RC2 freigegebenen Gates und
die tatsächlich unterstützten Fähigkeiten sind in Release und
`STATUS.md` verknüpft.
