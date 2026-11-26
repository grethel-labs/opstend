# 04 · Proxmox HA, Storage, Netzwerk und Wartung

Karten PH01–PH03 in [Proxmox](../proxmox.md). Stand der Recherche 2026-11-24.
PVE führt die Platzierung und den Wiederanlauf der aufgenommenen Gäste
durch. Steward vergleicht Eignung, beantragt konkrete native Aktionen und
führt ihre Belege zusammen. Der [Steward-Rollenwechsel](07-steward-ha.md)
hat ein eigenes Quorum und einen eigenen Ausfallablauf.

## Topologien und Toleranz

| Topologie | Mehrheitsverhalten bei Standardstimmen | Operative Auswirkung |
|---|---|---|
| 3 PVE-HA-NUCs + 4 einzelne NUCs + Beelink | 2 von 3 für das PVE-Cluster. Einzelhosts hängen von ihrer eigenen lokalen PVE-Instanz ab. | Empfohlener erster Abnahmepfad. Ein beliebiger Verlust eines der drei Mitglieder hält die PVE-Mehrheit, sofern die anderen erreichbar bleiben. Gastwiederanlauf braucht zusätzlich passendes Netz, Storage und Kapazität. |
| Ein PVE-Cluster aus sieben NUCs + Beelink separat | 4 von 7. Eine Platzierungsregel für drei NUCs ändert die Zahl der Stimmen nicht. | Mehr gemeinsame PVE-Dienste. HA-Gäste bleiben von den erlaubten Zielknoten abhängig, selbst wenn andere Knoten das Quorum sichern. |
| Alle PVE-Hosts eigenständig | Jeder Host verwaltet seine eigene Instanz. | Gemeinsame Steward-Richtlinien bleiben möglich. Ein Gast auf ausgefallenem Host braucht Wiederanlauf des Hosts oder freigegebenen Restore auf einem anderen Ziel. |
| Zwei PVE-Knoten plus QDevice | Eigenes von PVE beschriebenes Modell mit externer Stimme und anderer Abhängigkeitskette. | Option für eine andere Installation mit eigener Abnahme. Das Modell ist keine Voraussetzung für das Drei-Knoten-Profil. |

PVE beschreibt den Cluster-Dateisystemzustand bei Quorumverlust als
schreibgeschützt. PVE verlangt für eine stabile Clusterkommunikation
zuverlässiges LAN mit Latenzen unter 5 ms zwischen den Knoten und
empfiehlt Trennung von Storage-/Transferlast. Eine VLAN-Trennung kann
Traffic ordnen. Gemeinsame physische Links, Switches und Stromversorgung
bleiben dadurch gemeinsame Ausfalldomänen.
[PVE Cluster Manager](https://github.com/proxmox/pve-docs/blob/master/pvecm.adoc)

### Datenpfadoptionen auf drei NUCs

| Option | Wiederanlauf bei Ausfall eines Compute-Hosts | Typische Engstelle | Reihenfolge für die Referenz |
|---|---|---|---|
| Beobachtetes lokales ZFS mit PVE-Replikation | Gast kann auf einem freigegebenen Knoten mit vollständigem, letztem Snapshot wieder anlaufen. Asynchronität lässt Daten seit der letzten bestätigten Replikation offen. | Kapazität auf Quell- und Zielknoten, Replikationsalter, Disk-Eignung für ZFS, zweiter Ausfall während Wiederaufbau. | Qualifizieren, wenn passende NUC-Datenträger vorhanden sind und Schutzklasse das beobachtete RPO akzeptiert. [PVE Storage Replication](https://github.com/proxmox/pve-docs/blob/master/pvesr.adoc) |
| Qualifizierter gemeinsamer NFS-/SAN-/Storage-Dienst | Erreichbarer gemeinsamer Gast-Storage kann direkt genutzt werden. Seine Ausfalltoleranz und Datenintegrität bestimmen die Verfügbarkeit. | Single Point of Failure bei einem Server oder Netzpfad, Latenz, Sicherung von Storage- und Netzwerkdiensten. | Vorhandenen redundanten Dienst zuerst auf echte Fehlerdomänen prüfen. Das Pi-NAS bleibt im Referenzprofil Dateispeicher. [PVE Storage Manager](https://github.com/proxmox/pve-docs/blob/master/pvesm.adoc) |
| Hyperkonvergentes Ceph/RBD | Abhängig von Pool-/Quorum-Konfiguration, verbleibenden OSDs und Betrieb während Rebalance. | Platzbedarf für Replikate, Netzwerk unter Recovery-Last, zusätzliche Daemons, gemeinsame Boot-/Datenplatten und Strom. | Spätere Supportvariante, wenn Benchmark und Fehlertest bei Last passen. Drei NUCs allein belegen keine Eignung. [Proxmox Ceph](https://github.com/proxmox/pve-docs/blob/master/pveceph.adoc) · [Ceph Hardware](https://docs.ceph.com/en/latest/start/hardware-recommendations/) |
| Lokaler Gast-Storage ohne erreichbares Replikat | Wiederherstellung vom letzten qualifizierten Backup nach Freigabe. | Dauer bis zur Bereitstellung eines Zielknotens und Nutzdatenprüfung. | Normal für eigenständige Rechner und lokale Gerätebindung. Keine PH03-Freigabe für diesen Gast. |

Steward speichert pro Gast einen zeitlich gebundenen
**Eignungsbefund**. Kriterien sind erlaubte Knoten, native HA-Regel,
Node-/PVE-Version, Ressourcenkapazität nach Reserven, Netz/Bridge/VLAN,
verfügbare Gast-Volumes und deren Replikationszeit oder die
Shared-Storage-Identität, CPU/Microcode, Architektur und lokale Geräte
oder Mounts. Anzeige und Admission lesen denselben Befund. Ein
Eignungsziel hat die Zustände `eligible`, `ineligible` oder `unknown`
und eine Liste der Gründe. Admission verlangt einen frischen Befund.

**N+1-Eignung prüfen.** Für jedes vorgesehene Szenario eines verlorenen
NUC wird die gemeinsame Platzierbarkeit der freigegebenen Gäste geprüft.
Ein freier Slot für jeden Gast einzeln beweist nicht, dass alle
betroffenen Gäste gleichzeitig überleben können. Reservierter RAM,
laufende Gäste, Storage- und Netzlimits bilden die Eingaben. Größere
Szenarien dürfen eine dokumentierte Reihenfolge und Priorität haben,
sofern die Abschalt- und Recovery-Politik ausdrücklich festgelegt ist.

## Migration und lokales KI-Profil

| Beobachtung | Konsequenz |
|---|---|
| QEMU soll live migrieren | PVE-Kompatibilität für CPU-Typ, Ziel, Storage und angeschlossene Geräte prüfen. Ein CPU-Typ `host` kann auf unterschiedlichen CPUs oder Microcode-Ständen zu fehlenden Flags führen. |
| LXC soll verlagert werden | Effektive Unterbrechung des qualifizierten Stopp-/Wiederanlauf- oder nativen Verlagerungspfads anzeigen. Mounts außerhalb des verwalteten Storages separat prüfen. |
| Beelink mit geplantem KI-Container | Hardwarefunktion, reservierter RAM und zusätzliche Geräte als Hostzuordnung sichtbar. Diese Angaben gelten auch bei Steward-Rollenplanung. |
| Gast enthält lokale Hardwarebindung | Nur die verifiziert geeigneten Zielknoten zulassen. Für verbleibende Fälle Wiederanlauf auf dem Host oder getesteten Restore vorsehen. |
| Wechsel Intel ↔ AMD oder amd64 ↔ arm64 | Den Nachweis pro geplantem Pfad verlangen. Proxmox garantiert Intel-AMD-Live-Migration laut QEMU-Guide nicht. Standort- und Flottenansicht kann unterschiedliche Architekturen inventarisieren. |

[QEMU CPU-Typen und Migration in PVE](https://github.com/proxmox/pve-docs/blob/master/qm.adoc) ·
[PVE HA Ressourcenanforderungen](https://github.com/proxmox/pve-docs/blob/master/ha-manager.adoc)

Cluster Resource Scheduler und ggf. die native automatische
Lastverteilung bleiben Autorität für PVE-HA-Gäste. Die
Steward-Dienstplatzierung behandelt ausschließlich Steward-Rollen.
Wartungsplanung für einen Knoten ist ein eigener, bestätigter Vorgang
mit heute beobachtetem Zustand. Clusterweites Disarm setzt PVE-HA-
Schutzmechanismen zeitweise außer Kraft. Steward zeigt diesen Status als
degradiert und nutzt ihn nicht als PH02-Wartungsaktion.
[PVE HA Manager und Cluster Resource Scheduler](https://github.com/proxmox/pve-docs/blob/master/ha-manager.adoc) ·
[PVE 9.2 Veröffentlichung](https://www.proxmox.com/en/about/company-details/press-releases/proxmox-virtual-environment-9-2)

## Operationelles Zustandsmodell

1. **Aufnahme.** Inventar und Herkunft für genau eine PVE-Instanz.
   Quorum, Ressourceneigentum und Betriebszustand bestätigen. Native
   HA-Aufnahme verlangt einen freigegebenen Backup-Beleg und
   Gastgeneration. Die später beobachtete HA-Zuständigkeit schließt den
   direkten Lifecycle-Schreibweg für denselben Gast.
2. **Geplante Wartung.** Plan bindet einen Node, aktuelle Gastliste,
   mögliche Zielknoten und Unterbrechungen, verbleibende Reserven,
   Laufzeitfenster und zugelassene native Methoden. Vor Ausführung
   werden Mitgliedschaft, laufende PVE-Aufträge und Kapazität
   erneut erhoben. Fortschritt berichtet erreichte Zustände pro Gast.
3. **Ungeplanter Ausfall.** PVE signalisiert verlorenen Knoten und
   Fencing-/Recovery-Zustand. Steward zeigt unklar, eingezäunt,
   in Wiederanlauf oder am Ziel verifiziert, jeweils mit Quelle.
   Schreiboperationen, die den nativen Ablauf kreuzen, bleiben
   gesperrt. Keine erzwungene Steward-Übernahme eines mutmaßlich
   noch aktiven Gastes.
4. **Rückkehr.** Neuer Readback für Quorum, native Platzierung und
   Nutzdaten. Steward protokolliert Rückkehr oder nach nativer Policy
   erfolgte Migration. Ein manueller Rückzug benötigt einen neuen Plan.

| Szenario | Nachweis in PH01–PH03 |
|---|---|
| Geplanter Verlust eines Nodes durch Wartung | Jeder freigegebene Gast bleibt erwartungsgemäß verfügbar oder hat belegte geplante Unterbrechung. Kapazitätscheck sperrt einen unzulässigen Zielknoten. |
| Hart ausgefallener Host | PVE-Quorum am Mehrheitsort, nativ beobachtetes Fencing und höchstens eine aktive Instanz pro Gast. VM und LXC jeweils mit Nutzdatenprobe. |
| Netzpartition 2 + 1 | Minderheitsstatus erkennbar. Native Schutzmechanismen erfüllen den dokumentierten PVE-Pfad. Recovery führt keine zweite Instanz ein. |
| Voller Quorumverlust | Keine neue schreibende Flottenaktion an die betroffene PVE-Instanz. Die UI zeigt den letzten belegten Zustand und dessen Zeit. |
| Fehlender Shared Store oder zu altes Replikat | Explizite Gast- und Zielblockade. Abgleich vorhandener Tasks, Anzeige des zulässigen Restore-Pfads. |
| WAN oder Pi-NAS ausgefallen | Getrennt verwaltete lokale Compute- und Quorum-Pfade bestehen fort. Abhängige Freigaben und Backup-Kopien werden in der Topologie als betroffen ausgewiesen. |

PH03 misst Wiederanlauf ab dem injizierten Testereignis bis zum
fachlichen Readback. Es protokolliert Hostausfall, Quorum, Ende des
Fencings, Start und Dienstgesundheit mit Quellen. RPO wird anhand des
letzten nachweislich wiederhergestellten Datenstands und der jeweiligen
Storage- oder Backupklasse bewertet. Ein Test auf verschachtelten Knoten
kann API-Pfade prüfen. Der physische Watchdog und verkettete
Fehlerdomänen erhalten ein eigenes reales Gate.
