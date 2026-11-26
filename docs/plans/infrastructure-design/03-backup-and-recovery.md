# 03 · Gemeinsame Sicherungsrichtlinien und Wiederherstellung

Karten BK09–BK11 in [Flotte](../fleet.md), CP01 für den Steuerzustand.
Stand der Recherche 2026-11-24. Die zentrale Oberfläche vereint Planung,
Nachweis und Wiederherstellung. Der Datenpfad folgt der Schutzklasse
und ihrem unterstützten Backend.

## Vergleich der Backup-Pfade

| Pfad | Stärken | Voraussetzungen und Grenzen | Verwendung |
|---|---|---|---|
| Native PVE-Sicherung zu PBS mit unabhängigem PBS-Pull | Gastkonfiguration und geschützte Gast-Volumes, native Restore-Integration, deduplizierte Speicherung, Namespace- und Sync-Verwaltung | PBS-Host und Datastore je Kopie, unabhängige Aufbewahrung, Repository-Rechte sowie recoveryfähige Verschlüsselungsschlüssel | Referenzpfad für PVE-Gäste. [PBS Installation](https://pbs.proxmox.com/docs/installation.html) · [PBS Remotes](https://pbs.proxmox.com/docs/managing-remotes.html) |
| Native PVE-Dateisicherung auf dafür qualifiziertem NFS-/CIFS-Storage | Einfacher lokaler Start und transportierbares Archiv. Ein NAS kann ein solches Ziel bereitstellen. | Mehr Daten für Vollarchive. Rechte, Performance, Dateisystemeigenschaften und Wiederherstellungsweg müssen geprüft werden. Ein lokales NAS ist im Standortausfall Teil derselben Ausfalldomäne. | Geeignet als lokales Betreiber-Backup und als beobachteter Altpfad. Automatismus für unabhängigen Archivexport braucht einen eigenen Nachweis. [PVE VM/CT Backup](https://github.com/proxmox/pve-docs/blob/master/vzdump.adoc) |
| Restic über HTTPS | Deckt registrierte Linux-/Anwendungsdaten und kleine externe Deployment- oder Steuerzustandsartefakte ab. Existierender Steward-Workflow mit Prüfung und Restore. | Verlässliche Erfassung vor Upload. Speicher, Egress, Laufzeit und getrennte Lese-/Schreib-/Prune-Rechte qualifizieren. | Bevorzugte Option für einen der Ubuntu-vServer. [Steward Backup Foundation](../../backup-foundation.md) · [rest-server](https://github.com/restic/rest-server) |
| PBS-Datastore mit S3-Backend | Entkoppelt Datastore-Volumen von VPS-Systemplatte. Seit PBS 4.2 offiziell unterstützt. | PBS bleibt als Server mit persistentem lokalem Cache nötig. Anbieter-, API-, Egress- und Restore-Kosten qualifizieren. Ein Datastore hat genau eine aktive PBS-Instanz. | Alternative für den externen PBS-Pfad nach separater Prüfung. Keine notwendige Voraussetzung für die erste M11-Abnahme. [PBS 4.2 Release History](https://pbs.proxmox.com/wiki/Roadmap#Proxmox_Backup_Server_4.2) · [PBS Backup Storage](https://pbs.proxmox.com/docs/storage.html) |
| Externes Offline- oder zeitweise getrenntes Medium | Übersteht Ausfälle oder Kompromittierung des online erreichbaren Standorts. | Bedienaufwand, Kopierintervall, Schlüsselzugriff und regelmäßig geprobter Rückweg. | Zusätzliche Betreiberoption für ausgewählte Schutzklassen. Eine online verfügbare Offsite-Kopie hat weiterhin eigenen Wert. [PBS Wartung](https://pbs.proxmox.com/docs/maintenance.html) |

PVE-Storage-Replikation, ein NAS-Spiegel und eine PBS-Kopie lösen
verschiedene Aufgaben. Storage-Replikation liefert einen Startpunkt für
Gastwiederanlauf. Ein Spiegel kann Plattenausfälle auffangen. Ein
versioniertes und unabhängig wiederherstellbares Backup schützt gegen
weitere Fehlerarten wie logische Löschung und Verlust des Standorts.
Im Katalog erhält jeder dieser Pfade seinen eigenen Status.
[HA und Speicher](04-proxmox-ha-and-storage.md)

## Was sich mit dem vorhandenen Aufbau prüfen lässt

1. Das Raspberry-Pi-NAS wird als Gerät und Dateispeicher registriert.
   Bei zwei nominell 2-TB-NVMe ergeben sich zum Beispiel für einen Spiegel
   ungefähr 2 TB vor Dateisystem- und Betriebsreserve. Zwei lokale
   Platten garantieren keine unabhängige Backup-Kopie. Nutze verfügbare
   Kapazität und Durchsatz aus dem tatsächlichen Layout. Ein Ausfall des
   Pi wird als betroffene Freigabe oder ausgefallenes Ziel ausgewiesen.
2. Wähle für native Gastbackups ein qualifiziertes x86-64-PBS-Ziel.
   Eine dedizierte Management-VM auf einem geeigneten NUC ist eine
   Option, falls lokaler, qualifizierter Datastore und Platz dafür
   vorhanden sind. Das Gastbackup-Protokoll terminiert an PBS. Die
   Steuerung speichert native Referenzen und Jobstatus.
3. Beide vServer werden zunächst als Ubuntu-26.04-LTS-Ziele verwaltet.
   Für einen externen Restic-Pfad kann einer davon nach Prüfung eine
   private, getrennt authentisierte HTTPS-Schnittstelle erhalten.
   8 GB RAM und 4 vCPU beschreiben Rechenressourcen, deren
   Backup-Kapazität aus Speicherplatz, Quota, Durchsatz,
   Transferlimits, Aufbewahrung und Wiederherstellung bestimmt wird.
4. Wähle für die externe PBS-Kopie ein eigenständig qualifiziertes Ziel.
   Optionen sind ein geeigneter externer PBS-Dienst oder eine
   separat betriebene PBS-Instanz mit unterstütztem OS und Storage.
   Eine Ubuntu-Installation wird als Linux-Host weitergeführt. Erhobene
   Informationen müssen belegen, welche Datenklasse damit extern
   geschützt ist. Bis zur fertigen Qualifikation zeigt die UI beim
   Gastbackup ausdrücklich den lokalen Stand und die fehlende Kopie.
5. Ein Repository mit wichtiger Wiederherstellungsfunktion wird nach
   Ausfalldomäne und administrativer Trennung beurteilt. Dass zwei
   vServer erreichbar sind, belegt weder verschiedene Provider noch
   unterschiedliche Regionen oder getrennte Löschzugriffe.

**Größenrechnung vor Freigabe.** Als erste Untergrenze gilt bei einem
Netto-Transfer von 20 Mbit/s für ein effektives 100-GiB-Archiv ungefähr
12 Stunden reine Übertragung. Das folgt aus 100 × 2³⁰ Bytes × 8 geteilt
durch 20 Millionen bit/s. Der echte Restore enthält zusätzlich Auth,
Backend-Lesen, Verifikation, Entschlüsselung, Schreiben, Start und
Nutzdatenprüfung. Für den Speicherbedarf sind die initialen eindeutigen
Daten, tägliche Änderungen und Retention, Metadaten, Prüfläufe sowie
temporäre Arbeits- und Mindestfreiraumgrenzen separat zu messen. Ein
theoretisches Deduplizierungsverhältnis reicht für ein zugesichertes RPO
oder RTO nicht aus.

## Schutzklassen, Rechte und Datennachweise

| Schutzklasse | Aufnahme und wichtige Deckungslücke | Ende eines echten Restore-Tests |
|---|---|---|
| PVE-VM | Registrierte VM-Konfiguration, einbezogene Disks, dokumentierter Konsistenzmodus. QEMU-Gastagent kann Freeze/Thaw beitragen. App-Konsistenz braucht einen eigenen geprüften Ablauf. | Neuer isolierter Gast startet. Geschützte Daten und Startpfad stimmen. Ausgeschlossene Disks sind im Bericht gelistet. |
| PVE-LXC | Rootfs und explizit gesicherte verwaltete Mounts. Bind-/Device-Mounts liegen außerhalb des nativen Sicherungsumfangs. | Neuer Container startet mit erwarteten Testdaten und dokumentierten Quell-Mounts. Externe Mounts werden separat wiederhergestellt oder als Lücke gezeigt. |
| Linux-Anwendung | Bestehende Erfassung über stimmigen Snapshot oder kontrollierte Pause, genau registrierte Daten, Restic-Quittung. | Restore auf leerem isoliertem Ziel, Datenintegrität und fachliche Leseprobe. |
| Steward-Steuerzustand | Verschlüsselter bestätigter Datenbanksnapshot, Release- und Schema-Hinweis, separat verwahrte Schlüssel und registrierte Zielreferenzen. | Isolierter Restore in neuer Generation, alte Schreibwege gesperrt, Auftrags- und Zielabgleich abgeschlossen. |

[PVE Backup-Modi und Volume-Deckung](https://github.com/proxmox/pve-docs/blob/master/vzdump.adoc) ·
[Steward HA Wiederanlauf](07-steward-ha.md)

Der Zustandskatalog führt **Capture**, **Backup im Primärziel**, **externe
Kopie**, **Integritätsprüfung** und **wiederhergestellte Nutzdaten** als
getrennte Ereignisse. Jedes Ereignis bindet die Ressourcengeneration,
Datenzeit, das konkrete Backend, Repository, Snapshot, Task, Phase und
Rechtedeckung. Bei einer nicht geprüften Kopie zeigt die Oberfläche
ihren Status getrennt von der letzten vollständig nachgewiesenen Kopie.
Eine einzelne erfolgreiche API-Antwort markiert weder Backup noch Restore
als abgeschlossen.

- **Produzent:** Schreibscope für seinen Namespace oder sein Repository,
  mit begrenzten Job- und Bandbreitenbudgets. Keine administrativen
  Löschrechte. Append-only rest-server schützt gegen eine Klasse
  versehentlichen oder kompromittierten Löschens durch den Upload-Client.
  Die Serveradministration und der separate Retentionweg bleiben eigene
  Vertrauensgrenzen. [rest-server](https://github.com/restic/rest-server)
- **PBS-Sync:** Offsite-Pull mit Quellleserechten und eingeschränktem
  lokalem Schreibscope. Eigene Retention am externen Ziel.
  `remove-vanished` bleibt deaktiviert. Externe Speicher- und
  Namespace-Verlusttests verwenden Testdaten. [PBS Remotes und Sync](https://pbs.proxmox.com/docs/managing-remotes.html)
- **Prüfer:** Leseberechtigung für freigegebene Repositories, begrenzte
  Datenprüfung und eigenes Acceptance-Receipt. Ein bloßes Listing
  unterscheidet sich von der Prüfung gespeicherter Datenblöcke.
  [Restic Repository Checks](https://restic.readthedocs.io/en/stable/045_working_with_repos.html)
- **Retention/Reparatur:** Eigenständige, eng gescopte Identität. Plan und
  Zeitfenster sind sichtbar. Prune/GC konfligiert mit Verfügbarkeit und
  Kapazität und wird separat eingeplant. [Restic Forget und Prune](https://restic.readthedocs.io/en/stable/060_forget.html)
- **Recovery:** Schlüssel und Anleitung werden unabhängig vom
  ausgefallenen Host gesichert. Schlüssel-ID und Quittung gehen in
  Inventar und Audit. Schlüsselwerte bleiben beim zuständigen
  Credentialpfad und dürfen im isolierten Restore praktisch auffindbar sein.

## Zeitplan, Wiederholungen und Drill

Ist ein nativer Zeitplan vorhanden, importiert Steward zunächst seine
Zuständigkeit und sein letztes Ergebnis. Eine zentrale Übernahme verwendet
FL03. Der Job bindet Schutzobjekt, Zeitfenster, Richtlinienrevision und
Executor-Autorität. Schreibende Phase und natives Ergebnis sind vor
Retry abzugleichen. Ein wiederaufgenommener Upload aus einem vorhandenen,
belegten Capture kann erneut angesetzt werden, sofern die Jobregeln ihn
erlauben. Ein neuer Gastbackup-Start hat eine eigene Wirkung und benötigt
erneute Vorbedingungen. Pro Quellhost und Ziel ist eine konfigurierbare
Obergrenze für I/O-lastige Jobs vorgesehen. Voller Speicher, Rückstau,
fehlender Schlüssel und fehlgeschlagene Prüfung sind unterschiedliche
Betriebszustände.

**Initiales Ziel im Referenzprofil.** Maximal 24 Stunden zwischen
Wiederherstellungspunkten für die freigegebenen Offsite-Schutzklassen.
Die UI zeigt das Alter des neuesten geeigneten externen Datenstands;
jüngere ungeprüfte Versuche bleiben sichtbar. RTO wird bis zur
bestätigten Nutzdatenprüfung gemessen. Ein erreichbares HTTP-Endpoint
liefert hierfür keinen Nachweis.

| Gate | Beweismittel |
|---|---|
| BK09 | Scope-Vorschau für VM, LXC, Anwendung und NAS-Abhängigkeit. Fehlende Offsite-Kapazität und doppelte Zeitpläne werden begründet abgewiesen. |
| BK10 | Echte PBS- und Restic-Quittungen. Ausfall des primären Testartefakts und ein fehlgeschlagener Sync führen zu nachvollziehbarem Status. Externe Kopie bleibt getrennt prüfbar. |
| BK11 | Ein isolierter nativer Restore aus externem PBS und ein isolierter Anwendungsrestore aus unabhängigem Restic. Zugriffs-, Schlüssel- und Netzfehler plus fachlicher Readback. |
| IR01 | Referenzflotte verliert NAS oder WAN im Test. Dashboard zeigt betroffene Kopien und verbleibende Pfade. Separate Steuerzustandswiederherstellung prüft Rollen und offene Jobs. |
