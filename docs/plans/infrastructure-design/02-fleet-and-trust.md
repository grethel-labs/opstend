# 02 · Flottenmodell, gemeinsame Einstellungen und Vertrauen

Karten FL01–FL03 in [Flotte](../fleet.md). Stand der Recherche 2026-11-24.
Die Flotte verbindet eigenständige PVE-Installationen, Cluster, Linux-Hosts,
Agenten und Geräte unter einer administrativen Sicht. Sie benötigt in M10
genau einen autoritativen Koordinator. Der Übergang zu Quorum steht in
[Steward HA](07-steward-ha.md).

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
Protokolle inspirieren Steward, ohne einen Kubernetes-Betrieb einzuführen.
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
Für explizit externe Aufgaben ist der Status verfügbar. Steward delegiert
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

## Sequenz für einen Gast-Neustart

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
