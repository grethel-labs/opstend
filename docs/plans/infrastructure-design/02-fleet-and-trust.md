# 02 · Flottenmodell, gemeinsame Einstellungen und Vertrauen

Karten FL01–FL03 in [Flotte](../fleet.md). Stand der Recherche 2026-11-24.
Die Flotte verbindet eigenständige PVE-Installationen, Cluster, Linux-Hosts,
Agenten und Geräte unter einer administrativen Sicht. Sie benötigt in M10
genau einen autoritativen Koordinator. Der Übergang zu Quorum steht in
[OpsTend HA](07-steward-ha.md).

## Vergleich der Konsistenz- und Bedienmodelle

| Modell | Stärke | Grenze im Referenzaufbau | Wahl |
|---|---|---|---|
| Einzelkonfiguration je Host, zentral gelesen | Sehr einfacher Umstieg. Ein Ausfall des Portals beeinflusst lokale Abläufe wenig. | Richtlinienänderungen müssen separat angefasst werden. Konflikte, Frische und Eigentum sind ohne Modell nur schwer belegbar. | Startmodus für Aufnahme und Trennung eines Hosts. |
| Ein autoritativer Flottenkopf, gültiger angewandter Stand je Ziel | Ein Vorschau-/Freigabefluss für CLI und Web. Offline-Ziele und Teilanwendung bleiben erklärbar. | Eine dauerhafte Absicht und nachgewiesener Vollzug je Ziel sind erforderlich. | M10. SQLite bis M14, lokale Anwendung erst nach Revision- und Freigabeprüfung. |
| Git als gewünschte Konfiguration | Review, Verlauf und nachvollziehbare deklarative Quelle. | Ein Git-Commit entscheidet nicht über frische Zustandsbelege, zeitkritische Operatoraktionen und bereits ausgelöste native Tasks. | Später möglicher Eingang für typisierte Vorschläge. Der Executor und die Flottenautorität bestätigen jede kritische Aktion. [OpenGitOps-Prinzipien](https://opengitops.dev/) |
| Unabhängige Schreiber mit späterer Merge-Auflösung | Lokale Bearbeitung auch während vollständiger Netztrennung. | Ein Merge kann kollidierende irreversible API-Wirkungen oder bereits erteilte Schreibfreigaben nicht rückgängig machen. | Beobachtungen dürfen zeitversetzt ankommen. Sicherheitsrichtlinien, Job-Claims und Eigentumswechsel haben eine einzige bestätigte Autorität. |

Optimistische Konkurrenzkontrolle genügt für Richtlinienänderungen, wenn
jede Änderung den gelesenen Kopf voraussetzt. Ein HTTP-Adapter kann dies
als `If-Match` darstellen. Serverseitige Vergleiche bleiben auch für
CLI, interne Aufträge und Wiederanlauf verpflichtend. Kubernetes
verwendet Ressourcen-Versionen vergleichbar für bedingte Änderungen und
für den zuverlässigen Übergang von Snapshot zu Ereignisstrom. Die
Protokolle inspirieren OpsTend, ohne einen Kubernetes-Betrieb einzuführen.
[HTTP If-Match](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match) ·
[Kubernetes API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)

## Identitäten und Lebensdauer

| Datensatz | Stabile Identität | Veränderliche Eigenschaften | Ersetzungsfall |
|---|---|---|---|
| Site | Steward-ID | Name, Kontakt, Netzbereich und Ausfalldomänen | Zusammenlegung ist eine neue Zuordnung im Verlauf. |
| PVE-Instanz | Steward-ID mit verifizierter Quelle | erreichbare Knotenendpunkte, PVE-Version, Anzeigename | Neuinstallation, zweifelhafte Kontinuität oder Join wird bestätigt, bevor Schreibrechte übernommen werden. |
| Physischer Host | Steward-ID mit aufgenommenem Host-/Agentenschlüssel | Node-Name, Hardware, RAM, Netz, Cluster-Mitgliedschaft | Ein Ersatz nach Totalausfall bekommt eine bestätigte Zuordnung mit eigener Schlüsselgeneration. |
| PVE-Gast | Instanz-ID, Typ, VMID und Steward-Gastgeneration | Platzierung, Name, Status und sichtbare Konfiguration | Unklare Wiederbelegung sperrt alte Freigaben. Verfügbare native Identitätsmerkmale sind versionsgebundene Belege. |
| Linux-Host oder Gerät | Steward-ID und belegte Adapter-/Agentenidentität | IP, Firmware/OS, Rollen und bereitgestellte Dienste | Ein geänderter Name oder DHCP-Lease setzt die Identität nicht zurück. Ein Geräteersatz braucht bestätigte Zuordnung. |
| Backup-Schutzobjekt | Scope, Ressourcengeneration, Backend und registriertes Repository | Schutzklasse, Richtlinie, geplante Kopien und letzte Prüfung | Quittungen historischer Generationen bleiben mit exakt ihrer Quelle verbunden. |

Mehrere PVE-Endpunkte werden erst nach Prüfung derselben aufgenommenen
Instanz zugeordnet. Transportidentität und Ressourcenidentität sind zwei
Belege. DNS, IP, Anzeigename, aktueller Knoten und Tag erlauben keine
automatische Verschmelzung. Bei Reihenfolgeproblemen bleiben
`inventory_generation`, `source_sequence`, beobachtete Zeit und
Empfangszeit getrennt. Ein vollständiger Snapshot mit berechtigtem Scope
kann verschwundene Objekte markieren. Teilansicht, Rechteentzug und
Ergebnislimit zeigen geringere Abdeckung. Sie können keine Löschung
autorisieren.

**Beispiel.** Zwei VMs mit derselben VMID auf unterschiedlichen
Virtualisierungsstandorten sind verschiedene Ressourcen. Wandert die
Cluster-VM nach Wartung auf einen anderen Clusterknoten, bleibt ihre
Identität erhalten. Wird dieselbe VMID nach einer Löschung neu vergeben,
wird die vorherige Backup-Historie weiterhin angezeigt. Die neue VM erbt
keine expliziten alten Berechtigungen oder Freigaben.

### Interner Identitätsvertrag (FL01.1)

`FleetIdentityRegistry` speichert die vergebenen Site-, Host-, Agenten- und
Instanz-IDs in der SQLite-Datenbank des Flottenkoordinators. Der bestätigte
Instanznachweis ist unabhängig von Anzeigenamen und Netzwerkadressen. Jeder
API-Pfad ist einer Instanz und einem Host zugeordnet und wird mit eigenem
Transportnachweis bestätigt. Die Methoden zum Registrieren und Bestätigen
sind interne Schnittstellen für den vertrauenswürdigen Koordinator.

Der Koordinator übernimmt die Gastbeobachtung aus dem nativen
`InventorySnapshot` über einen bestätigten API-Pfad. Die Position im Cluster
ist Teil der Beobachtung. Eine andere native Gast-UID mit neuerer
Registrierungszeit belegt eine neue Generation. Bei unklarer Kontinuität
bindet eine ausdrückliche Bestätigung die Entscheidung an die beobachtete
Generation und Beobachtungs-ID. Die serialisierbare Lesesicht zeigt die
vergebenen IDs und den Gaststatus. Der Koordinator hält Identitätsnachweise,
native Gast-UIDs und Registrierungszeiten intern.

PX02 liefert eine auf das API-Token begrenzte Sicht. Ein fehlender Gast in
dieser Sicht lässt die bisherige Generation bestehen. Nur ein erfolgreicher
Snapshot kann eine Generation als abwesend markieren, wenn der Koordinator
den vollständigen Gastumfang für genau diese Beobachtung und ihren API-Pfad
bestätigt. Historische Generationen bleiben erhalten.

## Richtlinien, Eigentum und Ausführung

1. Die Flottenbasis setzt Vorgaben und harte Obergrenzen. Site oder Gruppe
   darf Werte im erlaubten Bereich präzisieren. Eine explizite Zielausnahme
   steht am Ende der Vorgabenkette. Widersprüche auf gleicher Ebene
   blockieren den Plan. Mengenwerte brauchen je Feld eine definierte
   Ersetzungs- oder Schnittmengenregel.
2. CLI und UI zeigen denselben kanonischen Plan. Er bindet **Plan-Digest,
   Zielmenge und Zielgeneration, Aktion und normalisierte Parameter, Kopf-
   und Policy-Revision, relevante Beobachtungsbelege, Freigabe, Gültigkeit
   und Idempotenzkennung**. Jede Änderung der Zielmenge erfordert eine
   neue Vorschau. Die Freigabe entsteht aus dem Identitäts- und Rollenkontext
   des Operators. Der Job transportiert keine Websitzung und keine Secrets.
3. Der Ziel-Executor prüft beim Start Rollenbindung, Ressourcengeneration,
   aktuellen lokalen Sicherheitsrahmen, Wartungsfenster, kill switch,
   Budget und Sperrbereich. Ein Flotten-Admin kann keine lokale
   Sicherheitsgrenze implizit erweitern. Readback schließt den Auftrag mit
   Ergebnis je Ziel. Ein Sammelauftrag kann teilweise erfolgreich sein;
   Rollback einer Richtlinie erzeugt eine neue Revision.
4. Zuständigkeit gilt je Ressource oder Zeitplan. Ein Übergang bestätigt
   den Stillstand alter Auslöser, wartet oder klärt aktive Jobs, setzt einen
   revisionsgebundenen Eigentümerwechsel und aktiviert den neuen Auslöser.
   Für eine Rückkehr in den Einzelbetrieb gilt dasselbe Verfahren. Während
   einer Trennung bleiben die zuletzt bestätigten Eigentümer verbindlich.
   Abgelaufene Freigaben werden beim Wiederverbinden verworfen.
5. Flottenweit widerrufene Rollen, Agenten und Freigaben wirken an der
   nächsten autoritativen Prüfung. Eine noch laufende native Aktion behält
   ihre Task-Evidenz. Der Koordinator muss abklären, ob sie beendet,
   fortgeschritten oder weiterhin unklar ist. Eine Offline-Notfalländerung
   durch den Betreiber wird beim Wiederverbinden als externe Änderung
   angezeigt und benötigt vor erneutem Flottenschreiben eine Prüfung.

Beobachtete externe Zustandsänderungen erhalten einen eigenen Actor-Beleg,
soweit die Plattform ihn bereitstellt. Ein Extern-Writer kann auch ein
PVE-Zeitplan, Terraform, native HA oder ein direkter Operator sein.
Für explizit externe Aufgaben ist der Status verfügbar. OpsTend delegiert
einen bestimmten tolerierten Zweck und bleibt mit der lokalen Grenze
kompatibel. Erfolg einer anderen Aktion wird nicht automatisch einem
offenen Steward-Job zugerechnet.

## Enrollment und Berechtigungswege

| Variante | Vorteil | Betriebsaufwand | Einsatz |
|---|---|---|---|
| Ausgehendes HTTPS mit mTLS und Zeitlimit | Ein gemeinsames Sitzungs-/Reconnect-Modell für LAN und WAN. Bindet Gegenstelle kryptografisch. | CA, Erstausgabe, Rotation und sichere Widerrufsentscheidung müssen betrieben werden. | Standard-Agent. Hostschlüssel lokal erzeugen, einmalige Einladung an erwartete Identität und Ziel binden, per Betreiber bestätigen. |
| WireGuard oder ein bestehender privater Transport | Gute Segmentierung und privat erreichbare Verwaltungsendpunkte. | Seine Mitgliedschaft ersetzt keine App-Rolle oder Zielbindung. Unterschiedliche Betreiber nutzen unterschiedliche Netze. | Optionaler Transport. [WireGuard-Protokoll](https://www.wireguard.com/protocol/) |
| Standardisierte Workload-Identitäten per SPIFFE/SPIRE | Etabliertes Modell für getrennte Trust Domains, dokumentierte Identitäts- und Bundlerotation. | Zusätzliche Server/Agenten und Verteilung des Trust Bundles. | M10 übernimmt die Trennung von Identität und Rolle. SPIFFE-Kompatibilität erst bei Bedarf und konkreter Vertrauensdomäne. [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/) |
| API-only PVE-Connector | Keine Änderungen auf dem PVE-Ziel. | PVE-Schnittstelle muss vom Connector aus erreichbar sein. Secret- und Egress-Trennung werden dort geprüft. | Für Betreiber mit vorhandenem PVE API- und TLS-Setup. [PVE API Tokens](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) |

Eine Einladung ist kurzlebig, einmal verwendbar und an Flotte, erwartete
Rolle und Schlüsselregistrierung gebunden. Der Agent speichert eigene
Schlüssel unter seiner Identität. Rotation braucht ein begrenztes
Überlappungsfenster, eine widerrufbare alte Identität und Tests mit alten,
neueren und unbekannten Bundles. Der Executor prüft eine aktuelle
Widerrufsliste beziehungsweise Autorität für neue schreibende Jobs. Ein
reiner Heartbeat begründet weder Rechte noch Befehlsvollzug.

Getrennte Sichten für Operator, Beobachter, Backup-Prüfer, Planer und
Ausführer verwenden dieselben fachlichen Ressourcenreferenzen. Die
Berechtigung eines Menschen leitet sich aus dem Site-/Ressourcen-Scope
seiner Sitzung ab. Die Agentenidentität trägt einen spezifischen Scope
für Daten oder Ausführung. Die Ausführung besitzt ihren eigenen engen
Credential-Pfad. Für die Graphansicht wird vor Suchabfragen, Kanten und
Aggregationen gefiltert. [Dashboards und Topologie](06-observability-and-ui.md)

### Enrollment und API-only-Inventar betreiben (FL01.2)

Der Koordinator läuft unter einem eigenen Konto und bindet HTTPS an eine
explizite private IP. Der Betreiber stellt die Server- und Client-CA bereit
und verwaltet deren Ausgaben. Das Zertifikat des Koordinators braucht einen
DNS- oder IP-SAN für den Agenten-Endpunkt. Agenten erzeugen und behalten ihre
privaten Schlüssel lokal und verwenden ein Client-Zertifikat für mTLS. Den
SHA-256-Fingerabdruck des öffentlichen Client-Schlüssels bestätigt der
Betreiber über einen unabhängigen Kanal. Die lokalen DB-Befehle laufen unter
dem Koordinator-Konto. Die Schlüsseldateien bleiben beim jeweiligen Dienst.

```sh
install -d -m 0700 /srv/opstend-fleet
db=/srv/opstend-fleet/fleet.db
opstend fleet register-site --db "$db" --name lab
opstend fleet register-host --db "$db" --site-id "$site" --name pve-a
opstend fleet register-agent --db "$db" --host-id "$host" --name pve-a-connector
# Im eigenen Prozess starten.
opstend fleet serve --db "$db" --bind 10.10.20.5 --port 8443 \
  --cert-file /srv/opstend-fleet/server.pem --key-file /srv/opstend-fleet/server.key \
  --client-ca-file /srv/opstend-fleet/client-ca.pem
```

Die Beispiele verwenden die zuvor ausgegebenen IDs in `$site`, `$host`,
`$agent`, `$instance` und `$route`. Für API-only bestätigt der Betreiber
`cluster-id`, antwortenden Knoten, API-Namen, numerische Adresse und
SHA-256 des DER-kodierten PVE-TLS-Leaf-Zertifikats aus unabhängiger,
vertrauenswürdiger PVE-Verwaltungssicht. Bei einem Cluster stammt
`cluster-id` aus dem Cluster-Eintrag von `/api2/json/cluster/status`, bei
Standalone aus dem einzigen lokalen Knoteneintrag. Das Register speichert
die native ID als Hash. Jeder weitere Cluster-Zugang wird für dieselbe
Instanz einzeln bestätigt.

```sh
opstend fleet register-instance --db "$db" --site-id "$site" \
  --kind cluster --native-id "$native_id"
opstend fleet confirm-route --db "$db" --instance-id "$instance" --host-id "$host" \
  --api-name pve-a.lab.example --node pve-a --address 10.10.30.21 \
  --native-id "$native_id" --leaf-sha256 "$leaf_sha256"
opstend fleet key-fingerprint --cert-file /path/to/verified-client.pem
opstend fleet issue-invite --db "$db" --agent-id "$agent" --capability pve_inventory \
  --route-id "$route" --key-fingerprint "$client_spki" --ttl 600 \
  --invite-out /srv/opstend-fleet/connector.invite
```

Die Einladung über einen geschützten Kanal zustellen und als Datei mit
Modus `0600` im Besitz des Agenten ablegen. Der PVE-Connector läuft im
Zielnetz. Verwende einen privilegiengetrennten PVE-API-Token und gewähre
`Sys.Audit` auf `/` für Benutzer und Token jeweils ohne Vererbung, damit
der Connector die Instanz prüfen kann. Die weiteren Leserechte richten sich
nach dem gewünschten Inventarumfang. Die lokale Token-Datei enthält die
vollständige Referenz `benutzer@realm!token=UUID`. Sie und die PVE-CA
verbleiben beim Connector.

```sh
opstend fleet enroll --endpoint https://fleet.lab.example:8443 \
  --cert-file /etc/fleet/client.pem --key-file /etc/fleet/client.key \
  --server-ca-file /etc/fleet/server-ca.pem --invite-file /etc/fleet/connector.invite
opstend fleet collect-pve --endpoint https://fleet.lab.example:8443 \
  --cert-file /etc/fleet/client.pem --key-file /etc/fleet/client.key \
  --server-ca-file /etc/fleet/server-ca.pem --pve-ca-file /etc/fleet/pve-ca.pem \
  --pve-token-ref file:/etc/fleet/pve.token
```

Für einen reinen Agenten lädt der Betreiber mit `--capability heartbeat`
ein und lässt `--route-id` weg. `opstend fleet heartbeat` verwendet dieselben
TLS-Optionen wie `enroll`. Rotation stellt eine Einladung für einen neuen
SPKI mit den Optionen von `issue-invite` und der aktuellen Generation aus.
Beim erfolgreichen Einlösen wechselt der Schlüssel atomar. Ein Widerruf
wirkt bei der nächsten autoritativen Anfrage.

```sh
opstend fleet rotate --db "$db" --agent-id "$agent" --generation "$generation" \
  --capability pve_inventory --route-id "$route" --key-fingerprint "$new_spki" \
  --invite-out /srv/opstend-fleet/new-connector.invite
opstend fleet revoke --db "$db" --agent-id "$agent" --generation "$generation"
opstend fleet guest-history --db "$db" --instance-id "$instance" --vmid 101
```

### Einen bestehenden Standalone-Host lesend übernehmen (FL01.3)

Registriere die Instanz mit `--kind standalone`, bestätige die Route und
enrolle den Connector mit `pve_inventory` wie oben beschrieben. Für die
Übernahme braucht der Koordinator die registrierte Instanz, die bestätigte
Route, den Connector mit seiner aktuellen Grant-Generation und die
unabhängig verifizierte native ID.

Auf einem Standalone-Host mit nativer OpsTend-Installation kann root optional
das lokale Profil exportieren. Der Export prüft die registrierte Installation
und ihre Units. Er enthält Profil, Knoten, installierte Version, Rollen,
Instanzbindung und Erhebungszeitpunkt. Stelle die Datei dem Koordinator über
einen geschützten Kanal als private reguläre Datei bereit.

```sh
(umask 077; opstend fleet export-pve-profile > pve-profile.json)
# Auf dem Koordinator. Ohne lokalen Export die letzte Option weglassen.
opstend fleet adopt-pve --db "$db" --instance-id "$instance" --route-id "$route" \
  --agent-id "$agent" --generation "$generation" --native-id "$native_id" \
  --local-profile /srv/opstend-fleet/pve-profile.json
```

Die Erhebung läuft auf dem Connector mit demselben PVE-Lesetoken und
derselben mTLS-Identität wie das Inventar. Sie zeigt PVE-Version, effektive
Leserechte und lokale Backup-Zeitpläne, deren explizite VMID-Liste vollständig
im bestätigten Inventar sichtbar ist. Zeitplanangaben beschränken sich auf
einfache Kalenderwerte. Bei anderen Kalendern bleibt die Kalenderangabe leer.
Der Status der Zeitplanquelle und die Token-Abdeckung gehören zur Anzeige.
Leere oder fehlende Evidenz erlaubt keine Aussage über die Erreichbarkeit
des Hosts oder die Abwesenheit von Zeitplänen, Gästen oder Backups.
Lokale Richtlinien, Dienste und Zeitpläne bleiben in lokaler Verantwortung.
Die lesende Übernahme vergibt keine Schreibrechte.

```sh
opstend fleet collect-pve-adoption --endpoint https://fleet.lab.example:8443 \
  --cert-file /etc/fleet/client.pem --key-file /etc/fleet/client.key \
  --server-ca-file /etc/fleet/server-ca.pem --pve-ca-file /etc/fleet/pve-ca.pem \
  --pve-token-ref file:/etc/fleet/pve.token
opstend fleet show-adoption --db "$db" --instance-id "$instance"
opstend fleet show-adoption --db "$db" --instance-id "$instance" --history
opstend fleet detach-pve --db "$db" --instance-id "$instance" --revision "$revision"
```

Die angezeigte Revision schützt das Trennen gegen konkurrierende Änderungen.
Trennen entzieht der Route ihre Connector-Grants, offenen Einladungen und
laufenden Erhebungen. Die Historie zeigt bis zu 20 bestätigte Beobachtungen
mit stabilen Auftrags- und Capture-Referenzen. Capture-Referenzen identifizieren
den Bezug zum Gast und belegen kein erfolgreiches Backup. Ein Erhebungsversuch
ersetzt die aktuelle Anzeige. Eine fehlgeschlagene Erhebung oder Evidenz,
die älter als fünf Minuten ist, lässt die aktuelle Anzeige leer.

Beim Upgrade verwendet der Koordinator dieselbe private Datenbank weiter.
Ein Neustart erhält die Registrierung und die Historie. Für den
Wiederanschluss dieselbe bestätigte Route, Instanzbindung und Agent-ID
verwenden. Während der Trennung kann nur der bisherige Connector eine neue
Einladung für diese Route erhalten. Die bekannten Routenmerkmale erneut
unabhängig prüfen und `confirm-route` mit denselben Werten wiederholen.
Danach `rotate` mit der beim Trennen ausgegebenen Grant-Generation und einem
frischen Schlüssel ausführen, erneut enrollen und `adopt-pve` mit der neuen
Grant-Generation wiederholen. Eine frische Erhebung liefert die aktuelle Sicht
unter denselben Ressourcen- und Referenz-IDs.

### Richtlinienrevisionen freigeben (FL02.2)

Die CLI und die Webapp zeigen dieselbe kanonische Vorschau mit exakten
Zielgenerationen, vorherigem Flottenstand, lokaler Sicherheitsrevision und
Gültigkeitsdauer. `policy-approve` bindet die Prüfung an den Plan-Digest.
Ein zwischenzeitlich geänderter Kopf erfordert eine neue Vorschau.
Die Freigabe erzeugt ein Ergebnis je Ziel. Ohne bestätigte lokale Übernahme
bleibt das Ergebnis ausstehend. `policy-rollback` legt eine neue gewünschte
Revision an, die erneut geprüft und freigegeben wird.

Der Koordinator vergibt mit `policy-grant` die Leseberechtigung `read` oder
die Freigabeberechtigung `write` für genau eine Site, Gruppe oder
Ressourcengeneration. Freigaben erfordern Schreibzugriff auf alle geplanten
Ziele. Für das Speichern und Exportieren vollständiger Revisionen sowie
Rollback ist Koordinatorberechtigung erforderlich. Diese Berechtigungen
sind unabhängig von den Rollenwerten einer geplanten Richtlinie.

Für die Webapp startet der Betreiber den Admin-API-Prozess für den
Koordinator mit `STEWARD_FLEET_POLICY_DB`, `STEWARD_FLEET_POLICY_SUBJECT`,
einem eigenen `STEWARD_STATE_DIR`, dem Admin-Token per Dateireferenz und
dem zugelassenen TLS-Ursprung. Der lokale Datenbankeigentümer vergibt
die Koordinatorrolle mit `policy-coordinator --subject` und widerruft
sie mit `--revoke`. Die Zielübernahme prüft den aktuellen Rollenstand.
Der Prozess liefert im
Flottenmodus die Webapp, Sitzung und `/api/fleet/policy`. Die Vorschau
entsteht über `POST /api/fleet/policy/preview`, die Freigabe über
`POST /api/fleet/policy/approve` mit `Idempotency-Key`. Die Ergebnisansicht
liest `GET /api/fleet/policy/approvals/{id}`.

FL02.2 bietet eine lokale Übernahme für ein Ziel auf demselben Rechner wie
der Koordinator. Beide Datenbanken müssen getrennte private Dateien auf
demselben Dateisystem sein. Die Übernahme prüft den aktuellen Kopf und
den freigegebenen Plan. Sie liest Sicherheitsgrenzen und angewandte
Revision aus der Datenbank des Ziels. Erst nach gemeinsamem Commit sind
Richtlinienstand und Ergebnis sichtbar. Die Übernahme schreibt
ausschließlich Richtlinienmetadaten.

`target-policy.json` enthält `target` und `limits`. `targets.json` enthält
die ausgewählten Objekte mit `kind`, `id` und `generation`. Beide Dateien
sind privat. Die folgenden Befehle laufen als Eigentümer der Datenbanken.

```sh
opstend fleet policy-target-configure --target-db "$target_db" --config target-policy.json
opstend fleet policy-target-report --db "$db" --target-db "$target_db"
opstend fleet policy-preview --db "$db" --revision "$revision" --targets targets.json
opstend fleet policy-approve --db "$db" --digest "$digest" --idempotency-key "$request_id"
opstend fleet policy-target-adopt --db "$db" --target-db "$target_db" \
  --approval "$approval" --digest "$digest"
opstend fleet policy-status --db "$db" --approval-id "$approval"
```

### Zielstand melden und Richtlinien nach Wiederverbindung übernehmen (FL02.3)

Für ein entferntes Ziel registriert der Koordinator einen eigenen Agenten
und bindet die Einladung mit `policy_target` an genau eine Zielgeneration.
`target.json` enthält dafür `kind`, `id` und `generation`. Ein Host-Ziel
gehört zum registrierten Host des Agenten. Für eine PVE-Instanz oder einen
Gast braucht dieser Host einen bestätigten API-Pfad zur Instanz. Die
Einladung, TLS-Dateien und private Zieldatenbank werden wie oben getrennt
bereitgestellt. Auf dem Koordinator läuft derselbe private mTLS-Dienst.
Die Zielbindung bleibt beim Schlüsselwiderruf und bei der Rotation beim
ursprünglich eingeschriebenen Agenten.

```sh
opstend fleet issue-invite --db "$db" --agent-id "$agent" --capability policy_target \
  --target target.json --key-fingerprint "$client_spki" --invite-out target.invite

# Auf dem Ziel nach policy-target-configure und enroll.
opstend fleet policy-target-sync --target-db "$target_db" \
  --endpoint https://fleet.lab.example:8443 --cert-file /etc/fleet/client.pem \
  --key-file /etc/fleet/client.key --server-ca-file /etc/fleet/server-ca.pem
```

Der Aufruf meldet den angewandten Stand und die aktuelle lokale
Sicherheitsrevision. Für die Übernahme denselben Befehl mit
`--approval-id "$approval" --digest "$digest"` ausführen. Der Koordinator
prüft beim Beanspruchen den aktuellen Kopf, die Zielgeneration, den
Geltungsbereich des Freigebenden und den Ablauf. Das Ziel prüft seine
lokalen Grenzen und die kurze Gültigkeit der Antwort unmittelbar vor der
Übernahme. Es speichert den neuen Stand mit dem lokalen Readback-Beleg.
Bei unterbrochener Bestätigung übermittelt der nächste Aufruf denselben
Beleg erneut. Die Ergebnisansicht zeigt bestätigte Übernahmen je Ziel an.

Ein getrenntes Ziel bleibt ausstehend, während andere Ziele ihre Revision
übernehmen können. Nach der Wiederverbindung kann es eine noch gültige
Freigabe übernehmen, wenn der gemeldete Stand weiterhin zur Vorschau
passt. Ein geänderter lokaler Sicherheitsstand erscheint als Konflikt in
der Verantwortung des lokalen Betreibers. Bericht, Vorschau und Freigabe
erneuern, wenn sich der Stand geändert hat oder die Freigabe abgelaufen
ist. Eine neue Revision oder ein Widerruf wirkt bei der nächsten Prüfung
für eine Übernahme. Bereits bestätigte Ergebnisse bleiben erhalten.

### Registrierten Gast starten (FL03.1)

Unter **Guest power** wählt der Operator einen registrierten QEMU- oder
LXC-Gast einer eigenständigen PVE-Instanz. Die Auswahl zeigt die Instanz
und den Knoten. Nach **Preview guest start** ermittelt der native
Executor den aktuellen Zustand. Die Vorschau zeigt Gastgeneration,
angewandte Richtlinienrevision, beobachteten Zustand und Ablauf. Erst
**Approve guest start** erlaubt dem Koordinator, den geprüften Auftrag
an den gebundenen Executor zu liefern. Die Auftragsansicht bleibt nach
Neuladen verfügbar. Sie meldet Erfolg, wenn der zugehörige native Task
abgeschlossen ist und PVE den Gast als laufend bestätigt.

Der Browser-Principal braucht Schreibzugriff auf die Gastgeneration und
die Rolle `operator` in der wirksamen, angewandten Richtlinie. Er muss
auch im lokalen Rollenlimit des Ziels stehen. Die native Installation
braucht ihre übliche PX03-Registrierung für `start` und einen dedizierten
Schreib-Token. Die FL02-Richtlinie für denselben Gast wird im privaten
Zielregister `/var/lib/opstend-pve-executor/fleet-policy.sqlite3`
angewandt. FL02 nutzt weiterhin ihren eigenen `policy_target`-Agenten.
Inventarsammlung und FL02-Zielmeldung müssen für eine neue Vorschau
aktuell sein. Der Koordinator verwendet jeweils eine Frist von fünf
Minuten.

Für die Befehlsausführung registriert der Koordinator einen weiteren
Agenten auf dem bestätigten Host. Die Einladung bindet den lokal
erzeugten Client-Schlüssel mit `pve_power_target` an exakt den Gast in
`target.json`. Nach dem Enrollment stehen `agent_id` und
`generation` im Grant. Die Power-Client-Dateien
`fleet-client.crt`, `fleet-client.key` und `fleet-controller-ca.crt` sowie
`fleet-power.json` liegen im lokalen Executor-Verzeichnis. Die Dateien
gehören root und haben Modus `0600`, das Verzeichnis hat Modus `0700`.
`fleet-power.json` enthält `controller_url` als privaten HTTPS-Endpunkt
sowie `agent_id` und `enrollment_generation` mit den beiden Grant-Werten.

```sh
opstend fleet issue-invite --db "$db" --agent-id "$power_agent" \
  --capability pve_power_target --target target.json \
  --key-fingerprint "$client_spki" --invite-out power.invite

# Auf dem Ziel nach dem Enrollment in einem regelmäßigen lokalen Service.
opstend fleet command-target-sync

# Auf dem Koordinator. Die lokale CLI verwendet den Principal local-coordinator.
opstend fleet command-preview --db "$db" --target target.json \
  --policy-revision "$revision" --action start --idempotency-key "$preview_key"
opstend fleet command-status --db "$db" --command-id "$command"
opstend fleet command-approve --db "$db" --command-id "$command" \
  --digest "$digest" --idempotency-key "$approval_key"
```

`command-target-sync` führt je Aufruf einen Abruf und die zugehörige
Meldung über den verifizierten, signierten PX03-Executor aus. Bis zum
nächsten Abruf bleibt ein freigegebener Auftrag ausstehend. Ein
abgelaufener oder durch neue Richtlinie bzw. Enrollment-Generation
überholter Auftrag kann keine neue Ausführung beginnen. Nach einem
unklaren Versand bleibt der Auftrag für den Readback vorgemerkt. Eine
Schlüsselrotation lässt bereits erfasste Arbeit für denselben Agenten
nachvollziehen.

## Sequenz für koordinierte Gastaktionen

1. Der Operator erhält Inventar und tatsächliche Capability für genau den
   sichtbaren Gast. Ein aktiver PVE-HA-Writer geht über PH02.
2. Jede Vorschau enthält den heutigen Head und die aktuelle Gastgeneration.
   Eine spätere Änderung blockiert die Bestätigung mit konkretem Konflikt.
3. Der Koordinator speichert den Job vor der Lieferung. Der Executor
   verifiziert Plan und lokale Regeln, beansprucht den Auftrag und ruft
   seine registrierte Aktion auf. Native Task-ID und Readback ergeben
   den endgültigen Status.
4. Ein offline gewordenes Ziel zeigt den Auftrag mit Ablauf und wartet
   ohne erneuten Schreibauftrag. Beim Wiederverbinden transportiert der
   Agent seine letzte angewandte Policy, Jobreceipts und die aktuelle
   Beobachtung mit Ereignis-Sequenz.

**Abnahme.** FL01 prüft gleiche VMIDs auf getrennten Instanzen, Rotation,
Widerruf und Adresswechsel. FL02 prüft gleichzeitig geänderte Köpfe,
widersprechende Regeln, Scope und ausstehende Revisionen. FL03 prüft
Sammelauftrag, verlorene Verbindung, eindeutigen Zeitplaneigentümer und
Rückkehr in den Einzelmodus. Ein Upgrade-Test nutzt eine vorhandene
RC1-Instanz und verwendet deren [Executor-Grenzen](../../extending.md).
