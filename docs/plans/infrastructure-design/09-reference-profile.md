# 09 · Referenzflotte, Platzierung und Kapazitätsplanung

Vertieft den [Referenzaufbau nach RC1](../../post-rc1.md#referenzaufbau-mit-lokalen-und-externen-systemen).
Stand 2026-11-24. Dieses Beispiel prüft die Kombination verschiedener
Geräte, Standorte, Betriebsprofile und Abhängigkeiten. Die Produktlogik
verwendet aufgenommene Ressourcen und Fähigkeiten.

## Konkrete Sicht der Referenz

| Knoten | Typ | Bevorzugter Anschluss | Beobachtung, Aktionen und Abhängigkeiten |
|---|---|---|---|
| NUC 1–3 | Drei Nodes einer PVE-Instanz | Bestätigte API-Endpunkte, optional native Steward-Agenten | QEMU, LXC, native HA, Quorum, Storage, Netz und Wartung. PVE-Instanz und drei Host-IDs bleiben separat sichtbar. |
| NUC 4–7 | Vier eigenständige PVE-Instanzen | Nativer Agent oder Connector | Gäste, einzelne Jobs, Backup und Host-Ressourcen. Einzeln verwaltbar und als Gruppe filterbar. |
| Beelink GTR9 Pro | Eigenständige PVE-Instanz | Wie andere PVE-Einzelhosts, plus explizite Fähigkeits- und Reservemeldung | VMs/LXC und später ein hostgebundener KI-Container. Tatsächlich beobachtete Reserven und Host-/Gast-RAM getrennt führen. |
| Raspberry Pi | Lokales Gerät und NAS, 2 × 2 TB NVMe | Lesend über registrierten Connector oder vorhandenen Metrikendpunkt | Freigabe, freier und nutzbarer Speicher, Erreichbarkeit, eigene Standortabhängigkeit. |
| Externer vServer A | Ubuntu 26.04 LTS, 8 GB RAM, 4 vCPU | Ausgehender Linux-Agent | Externer Beobachtungsstandort für ausdrücklich registrierte Dienste, optional Host-Workloads mit eigenem Executor. |
| Externer vServer B | Ubuntu 26.04 LTS, 8 GB RAM, 4 vCPU | Ausgehender Linux-Agent und gegebenenfalls eigenes Backup-Profil | Optionales Restic-HTTPS-Ziel, soweit Quota, Speicher, Kosten, Restore und unabhängige Ausfalldomäne passen. |

Das ergibt sechs PVE-Instanzen mit acht physischen PVE-Nodes, zwei
externen Linux-Zielen und einem explizit
registrierten NAS. Ein lokal betriebener PBS-Dienst oder ein
Management-Gast ist eine zusätzliche Software-/Workload-Ressource
unter seinem tatsächlichen Host. Er zählt nicht als weiterer
physischer Host. Standort- und Hostbeziehungen behalten die
Belegquelle. Die Aliasnamen stehen für Testrollen.

## Illustratives Flottenmanifest

Die folgende Darstellung dokumentiert Beziehungen und Fähigkeiten.
Das tatsächlich implementierte Schema wird erst in den zuständigen
Karten festgelegt. Ressourcen werden registriert, über konkrete
Nachweise freigegeben und durch denselben Datenvertrag identifiziert.

```yaml
sites:
  - id: local-lab
    failure_domains: [local-power, local-network]
  - id: external-a
    failure_domain: pending-provider-check
  - id: external-b
    failure_domain: pending-provider-check
pve_instances:
  - id: lab-ha
    members: [nuc-1, nuc-2, nuc-3]
    placement_authority: proxmox-ha
  - id: nuc-4
    members: [nuc-4]
  - id: nuc-5
    members: [nuc-5]
  - id: nuc-6
    members: [nuc-6]
  - id: nuc-7
    members: [nuc-7]
  - id: inference-host
    members: [beelink]
    reserved_workload: dedicated-inference
devices:
  - id: local-nas
    site: local-lab
    capabilities: [capacity-observation, share-observation]
    raw_disks: [2 TB NVMe, 2 TB NVMe]
linux_targets:
  - id: vps-a
    site: external-a
    os: Ubuntu 26.04 LTS
    memory: 8 GB
    vcpu: 4
  - id: vps-b
    site: external-b
    os: Ubuntu 26.04 LTS
    memory: 8 GB
    vcpu: 4
control_plane:
  candidate_voters: [management-on-nuc-1, management-on-nuc-4, management-on-nuc-5]
  active_per_role: 1
  requested_hot_standbys: 2
```

Die externen Standorte sind eigene logische Scopes. Eine getrennte
physische Ausfalldomäne wird erst bei bekannter Region, Anbieter,
Account-/Admintrennung und geprüftem Netz- und Strompfad eingetragen.
Im lokalen Beispiel können Strom, Switch und Internetrouter weiterhin
gemeinsam ausfallen. Die Auswahl `nuc-1, nuc-4, nuc-5` ist ein
Platzierungsvorschlag, dessen Kapazität und getrennte lokale Startpfade
CP01 prüft.

## Erhebung vor dem Hardware-Gate

| Information | Entscheidung, die davon abhängt | Karte |
|---|---|---|
| Tatsächliches PVE-Release, Plattform-ID, CPU-Generation/Architektur, Firmware und Microcode pro Host | Unterstützte Adapteroperationen und zulässige Migrationsziele | PX01, PH01 |
| RAM absolut sowie für Host und Workloads freier und reservierter Anteil, Storage und I/O-Latenz | Eignung für Gastmigration, Quorum und KI; Reservebedarf bei Einzelausfall | PH01, CP03 |
| Schnittstellen, Netzpfade und Volllast-Jitter | Corosync, Backup- und Migrationsbudgets, getrennte Quorum-Pfade | PH01, CP01 |
| Pi-Modell, NVMe-Anschluss und Layout, Protokoll, messbare Kapazität und Zuständigkeit | NAS-Aufnahme, Aufbewahrung, Verfügbarkeit von Freigaben und lokales Backup | BK09, IN02 |
| Untertyp der Servervirtualisierung, CPU-Architektur, Systemd, Disk- und Transferquoten, Provider/Region | Linux-Capabilities, externes Restic-Ziel, erreichbarer Recovery-Pfad | BK09, IN01 |
| Native Gast-Disks, Bind-Mounts, optionale Geräte und Anwendungen mit eigenem Datenpfad | Tatsächliche Backupdeckung, Eignung für HA und konkrete Nutzdatenprobe | BK09, PH01 |
| Relevante Fehlerdomänen und zulässige Testziele | Evidenzumfang, Host-/NAS-/WAN-Drill und Quorumtest | PH03, CP01, IR01 |

Reale Hostkonfiguration und Credentials liegen in privaten
Testreceipts. Ein Release-Beleg enthält abstrahierte Gerätetypen,
Versionen, Testrollen und Fehlerdomänen, die fürs Ergebnis nötig sind.

### Rechenbeispiele für Entscheidung und Lasttest

- **RAM.** Beispiel mit 32 GiB physisch, einer 4-GiB-Hostreserve,
  18 GiB verbindlich zugewiesenen Gästen und 4 GiB dedizierter
  Betriebsreserve. Das ergibt 6 GiB Planungsreserve. Ein
  ausschließlich zur Beschleunigung der Inferenz reservierter
  Speicheranteil wird als eigene Reservation genau einmal
  abgezogen. Observed- und Config-Werte werden getrennt, um
  deklarierte und bereits belegte Speicheranteile ohne
  Doppelrechnung zu berücksichtigen.
- **Backups.** Beispieldaten mit 250 GiB initial eindeutigem
  Inhalt und 8 GiB täglich zusätzlich behaltenem Inhalt.
  30 Tage Änderungen ergäben zusammen rund 490 GiB vor
  Metadaten, Backend-Arbeitsreserve und zusätzlichem
  Storage-Overhead. Bestandsdaten erfordern gemessene Unique-
  Byte-Beobachtungen, da Volumenwachstum und Deduplizierung
  je Workload variieren. [Dimensionierung und Restore](03-backup-and-recovery.md)
- **Netzwerk.** I/O-lastige Restore-, Verify-, Scan- und Simultan-
  Backups werden unter realistischen parallelen Workloads gemessen.
  Die Flotte braucht neben stabiler Leerlaufmessung eine Messung
  unter erwarteter Netz- und Storagelast. Korrelation nutzt Last,
  Richtung, Dauer und Quelle, damit Quorumverluste wegen
  Storage-/Netzkongestion vom echten Hostausfall unterscheidbar sind.
- **Laufzeitkosten.** Erst Speichernutzung, Requests, Egress,
  Aufbewahrung und bereitgestellten Restore-Speicher summieren.
  Der Standort eines Repositorys ist zusätzlich Teil seiner
  Wiederherstellungsfehlerdomäne. Die Freigabe erfolgt anhand
  des konkreten Tarifs und einer realistischen Restore-Probe.

## Beispiel: Was bei welchem Ausfall noch funktioniert

| Ausfall | Weiterhin erwartete unabhängige Pfade | Als beeinträchtigt zu zeigen |
|---|---|---|
| Ein PVE-HA-NUC | PVE-Mehrheit, geeignete native Gastwiederherstellung, andere PVE-Instanzen. Steward-Quorum, falls höchstens ein Stimmberechtigter betroffen ist. | Host und seine Ressourcen, Zeitpunkt der letzten Beobachtung; ggf. vorherige Platzierung, Replikationsalter und Wiederanlauf. |
| Ein einzelner Nicht-HA-Host | PVE-HA-Gruppe, andere Einzelhosts und bei verbleibender Mehrheit die Steward-Rolle. | Seine nativen Gäste bis Hostwiederkehr oder Restore; lokal gebundene Geräte und Jobs. |
| Beelink | Deterministische Verwaltung, solange ihre Pfade weiter verfügbar sind. | KI-Dienst und Geräte-/Cache-gebundene Workloads auf diesem Host. |
| Raspberry Pi | Unabhängige PVE-Gastdisks, Steuerzustand sowie separat bereitgestellte Offsite-Ziele. | Betroffene Freigaben, abhängige Dienste und lokale Export-/Backup-Ziele. |
| WAN oder ein externer vServer | Lokal erreichbare Steuerung, lokales PVE-Quorum und lokale Jobs nach ihrer jeweiligen Policy. | Site-spezifische Beobachtung, Zielerreichbarkeit, Backlog und externes Kopier-RPO. |
| Vollständiger lokaler Standortverlust | Die tatsächlich qualifizierte externe Recovery- und Backup-Evidenz. | Beide lokalen Mehrheiten. Ein Wiederaufbau startet autorisiert in neuer Steward-Generation. |

Die Fehlerfälle werden gezielt und einzeln innerhalb der vorgesehenen
Milestone-Batches geprüft. Umfang und Beleg sind in
[Abnahme bis RC2](08-delivery-and-iterations.md) verknüpft.
