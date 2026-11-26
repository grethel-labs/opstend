# 11 · Vergleich bestehender Infrastrukturwerkzeuge

Stand der Recherche 2026-11-24. Grundlage sind Produktdokumentation,
offizielle Quell-Repositories und Spezifikationen. Die Tabelle
vergleicht dokumentierte Fähigkeiten und Architekturentscheidungen.
Messungen sind bei der [Abnahme](08-delivery-and-iterations.md) verortet.
Der geplante Steward-Umfang steht im [Fahrplan](../../post-rc1.md).

## Welche Produkte lösen welchen Teil?

| Produkt oder Ansatz | Vergleichbare Stärke | Konsequenz für OpsTend und den Referenzaufbau |
|---|---|---|
| **PVE und Proxmox Datacenter Manager** | PVE liefert die native Autorität. PDM bietet eine zentrale Sicht auf PVE/PBS, RRD, Gastzustand, native Aktionen und Migration über Remotes. | PDM ist der nächstliegende Vergleich für M9–M12. PVE/PBS bleiben Quellen. Eine PDM-Installation kann parallel laufen; wer ausschließlich PVE/PBS zentral bedienen will, hat damit bereits einen nativen Pfad. OpsTend verbindet daneben Linux, NAS, Geräte, gemeinsame Betriebsrichtlinien und Recovery-Evidenz. [PDM Einführung](https://pdm.proxmox.com/docs/introduction.html) · [PDM Remotes](https://pdm.proxmox.com/docs/remotes.html) |
| **Cockpit** | Unmittelbare, vertraute Linux-Systemverwaltung mit Host-, Storage-, Netzwerk-, Dienst- und Metriksicht; systemd-Aktivierung und Hostwechsel. | Guter nativer Detailzugang für Linux. OpsTend priorisiert site-übergreifende Richtlinie und kontrollierte Fachaktionen pro Ressource; bestehendes Cockpit kann daneben betrieben werden. [Cockpit Project](https://cockpit-project.org/) · [Feature Internals](https://cockpit-project.org/guide/latest/features.html) |
| **Zabbix mit Proxys** | Erfassung im Zielnetz, Pufferung bei unzuverlässigen Leitungen und späterer Versand zum Server. | Vergleich für den Pi-/Geräteanschluss und die beiden externen vServer. OpsTend übernimmt Beobachtungszeitpunkt und Quellstatus in den Fachkontext. Eine vorhandene Zabbix-Installation käme später als begrenzte Datenquelle infrage. [Zabbix Distributed Monitoring](https://www.zabbix.com/documentation/current/en/manual/concepts/proxy/distributed_monitoring) |
| **NetBox** | Gezielt gepflegte Referenzdaten für Standorte, Geräte, IP, Verkabelung und Virtualisierung. | Vorbild für deklarierte Beziehungen und Herkunft. OpsTend ergänzt aktuelle Beobachtung, Aktion und Jobquittung. Ein späterer Import behält Quellidentität und Verantwortlichkeit. [NetBox Einführung](https://netbox.readthedocs.io/en/stable/introduction/) |
| **Ansible AWX** | Inventare, Workflow-Templates, Abhängigkeiten, Freigabeknoten und verfolgte Ausführungen über mehrere Ziele. | Hilfreiches Vorbild für jobbezogene Bedienung. Frei parametrisierte Playbooks bleiben ein Betreiber-Workflow. OpsTend verwendet begrenzte Aktionsschemas und prüft native Nachrichten und Readback. [AWX Workflow Job Templates](https://docs.ansible.com/projects/awx/en/24.6.1/userguide/workflow_templates.html) |
| **OpenTofu / Terraform** | Versionskontrollierte deklarative Infrastruktur, State und importierbare Ressourcen. | Externe Policy-Quelle oder konkurrierender Writer bei Überschneidung. OpsTend zeigt Eigentümerschaft und bietet expliziten Übergang; native live Aktionen bleiben mit eigener Freigabe verbunden. [OpenTofu State](https://opentofu.org/docs/language/state/) |
| **Xen Orchestra** | Zeitpläne, getrennte Replikationsarten, Backup-Kopien und Wiederherstellungs-/Gesundheitstests für die Xen-Plattform. | Vergleich für die Usability des Backup-Katalogs. Ein gestarteter Gast mit geladenen Gasttools und die fachliche Nutzdatenprobe sind unterschiedliche Akzeptanzbelege. Für PVE bleibt die native PBS-Integration maßgeblich. [XO Backup Overview](https://docs.xen-orchestra.com/backups-and-dr/backup) · [XO Backup Settings](https://docs.xen-orchestra.com/backups-and-dr/backup-features-and-settings) |
| **Harvester** | Kubernetes-basierte, integrierte Hyperconverged Infrastructure mit eigener Plattform, VMs, Storage und Netzen. | Vergleich für eng integrierten Plattformbetrieb. Die vorhandenen PVE-Hosts, der Pi und Ubuntu-vServer profitieren im Referenzaufbau von Plattformanschlüssen ohne verpflichtende Neuinstallation. [Harvester Overview](https://docs.harvesterhci.io/v1.7/) · [Hardware and Network Requirements](https://docs.harvesterhci.io/v1.7/install/requirements/) |
| **Incus** | Verwaltete Container und VMs, Cluster-Mitgliedschaft und eigene verteilte Datenbank. | Später möglicher eigenständiger Adapter bei konkreter Nachfrage. Die Adaptergrenze hält native Incus- und PVE-Semantik getrennt und liefert gemeinsame beobachtete Eigenschaften. [Incus Clustering](https://linuxcontainers.org/incus/docs/main/explanation/clustering/) |
| **Prometheus/Grafana und OpenTelemetry** | Ausgereifte Metrikabfragen, Visualisierung und exportierbare Telemetrie über Quellen hinweg. | Bestehende Installationen können später eingebunden werden. OpsTend verbindet gemessene Signale mit Ressourcenzuständigkeit, Policies und Aktionsbelegen. [Prometheus Metric/Label Naming](https://prometheus.io/docs/practices/naming/) · [Grafana Datenquellen](https://grafana.com/docs/grafana/latest/administration/data-source-management/) · [OTel Collector](https://opentelemetry.io/docs/collector/) |

## Entscheidungen nach Einsatzfall

| Bedarf | Niedrigster sinnvoller Betriebsumfang | Steward-Nutzen im nächsten Schritt |
|---|---|---|
| Ein PVE-Host mit gelegentlicher lokaler Bedienung | PVE selbst; optional nativer Steward-Einzelhost bei gemeinsamem Plan-/Backup-Bedarf | Begrenzte signierte Installation und dasselbe Konfigurations-/Auditmodell wie in der späteren Flotte |
| Mehrere PVE-/PBS-Instanzen ausschließlich zentral bedienen | PDM passt bereits zu diesem Umfang. | Ergänzend gemeinsame Anwendungssicht, Hostrichtlinien, resticbasierte Daten und Workflowgrenzen. |
| Linux-Hosts und Pi in derselben Betriebsübersicht | Linux-Agent und registrierter Speicher-/Geräteconnector, optional bestehendes Monitoring | Gemeinsame Topologie und Ausfallbeziehungen, gestufte Richtlinien, Lastgrenzen und genaue Quellabdeckung |
| Ein unabhängiger externer Sicherungsort | Qualifiziertes PBS- oder Restic-Ziel je Datenklasse, verifizierter Datenzugriff | Schutzkatalog, Job- und App-Evidenz, RPO/RTO und freigegebene Restore-Übungen |
| Automatische Übernahme des Steward-Koordinators bei lokalem Ausfall | Drei Voter und geeignete Kandidaten; ein privater Zugang ohne Einzelabhängigkeit | Primär- und Ersatzrollen, gesicherte Claims und unabhängiger Wiederaufbau |
| Betrieb eines zweiten Hypervisors | Bedarf und echte Testinstallation einer weiteren Plattform | Neue Adapter-Capabilities und Supportzeile, dasselbe Inventar- und Rechtekonzept |

Die produktentscheidende Kombination ist ein gemeinsamer,
nachvollziehbarer **Ressourcen-, Berechtigungs-, Auftrags- und
Recovery-Kontext**. Management-Writes bleiben beim zuständigen
nativen Adapter oder lokalen Executor. Zusätzliche Plattformen
erweitern die Coverage nur mit einem belegten Adapter.

## Quellenpflege und Reproduzierbarkeit

- Dokumentation und Quellcode belegen Verhalten zum jeweiligen
  Versionsstand; PVE-Quelllinks auf `master` dienen zur Recherche.
  PX01–PX03 halten vor Freigabe tatsächlich getestete Versionen,
  API-Schema, Paketstand und Capability-Gates fest.
- Geplante Grenzen, Benchmarks und Hardwarealternativen sind in den
  Themenakten als Vorschläge markiert. Anbieterinfos, ARM-Support,
  Treibermatrizen, Protokollprofile und Tool-Releases werden bei
  Start der jeweiligen Karte erneut gegen die Primärquelle geprüft.
- Kosten, nutzbare SSD-/VPS-Kapazität, Netzpfade, Privilegien und
  Fehlertoleranz werden anhand des konkret betriebenen Ziels qualifiziert.
  Das Rechercheergebnis ändert keine bestehende Support-Aussage.
  [Bestätigte Baseline](../../support-matrix.md)
- Bei zwei Quellen mit unterschiedlichem Veröffentlichungsstand
  entscheidet die belegbare Version des Produkts. Beispiel ist
  S3-Storage in PBS 4.2, dessen Status von Preview zu offiziell
  unterstützt wechselte; die Unterstützung des konkreten
  Datastores ist eine eigene Steward-Abnahme.
  [PBS 4.2 Release History](https://pbs.proxmox.com/wiki/Roadmap#Proxmox_Backup_Server_4.2)
