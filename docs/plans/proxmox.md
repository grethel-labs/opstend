# Karten für Proxmox VE nativ und Proxmox HA

Reihenfolge, Budgets und Referenzaufbau stehen im
[Plan nach RC1](../post-rc1.md). Einstiegspunkte benennen heutige Module;
neue Adapter, Profile und Gate-Skripte werden in der jeweiligen Karte ergänzt.
Für konkrete API-Methoden und Privilegien zählt das unterstützte Release.

[Varianten für Installation und Gastaktionen](infrastructure-design/01-proxmox-native.md) ·
[Vergleich der PVE-HA- und Storage-Profile](infrastructure-design/04-proxmox-ha-and-storage.md)
[PVE-Benutzerverwaltung](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc) ·
[PVE API Viewer](https://pve.proxmox.com/pve-docs/api-viewer/)

## PX01 — Native Installation und Preflight

**Voraussetzung:** RC1 mit freigegebener Signatur- und Installationskette.
**Einstieg:** Release-Verifikation aus S01, Ansible-Preflight,
`core/config.py`, `core/render.py` und bestehende systemd-Härtung.

1. Implementiere ein versioniertes natives Profil für zunächst eine
   unterstützte PVE-Version auf x86-64. Der Preflight prüft PVE-Version,
   Architektur, API-Zugriff, Zertifikat, Installationsmodus, Ressourcen und
   Paket-/Unit-Konflikte. `plan` zeigt die getrennten Steward-Dateien,
   servicebezogenen Benutzer und Ports.
2. Installiere den Agenten nativ unter systemd mit eigener Identität, Datenpfad
   und kontrolliertem API-Zugriff. Das Einzelhostprofil kann CLI und lokale,
   privat erreichbare Bedienoberfläche auf demselben Host betreiben. Die
   Slot-Auswahl im Agentenmodus lässt zentrale Dienste deaktiviert. Die
   PVE-Paketverwaltung verbleibt beim Betreiber. Das RC1-Host-Hardening für
   Workload-Server wird auf PVE durch einen eigenen, begrenzten Installationspfad
   ersetzt.
3. Führe signiertes Upgrade und geordneten Rückbau aus. Der Rückbau entfernt
   Steward-Units und -Paketdateien, kann den Anschluss widerrufen und exportiert
   auf Wunsch seine Konfiguration. Beibehaltene Steward-Daten und
   operatorverwaltete Credentials werden im Plan ausgewiesen.

**Check/done**: Autorisierter PVE-Testhost mit vorhandener Test-VM und Test-LXC.
Preflight bleibt lesend, zweiter Installationslauf meldet `changed=0`;
Upgrade, Neustart und Rückbau lassen PVE-API, SSH, PVE-Pakete, Firewall,
Bridges, Storage und vorhandene Gäste funktionsfähig. Ein unzulässiger
Paketkonflikt und ein ungültiges Release werden vor der Installation erkannt.

## PX02 — Natives Inventar und API-Vertrag

**Voraussetzung:** PX01. **Einstieg:** `core/inventory.py`,
Beobachtungsprojektionen und der Read-only-Pfad der Admin-API.

1. Erfasse per PVE-API Knoten, QEMU-VMs, LXC, Pools, sichtbare Datastores,
   Gast-Netzwerkzuordnungen, Messkurven und Task-Status. Normalisiere
   Einheiten und vermerke Quelle, Erfassungszeit, Rechteabdeckung und
   unterstützte Capability je Ressource. Nutze ein explizit registriertes
   PVE-Ziel mit geprüfter TLS-Identität, eigener Leseberechtigung und
   begrenzten Timeouts.
2. Zeige Inventar und Gastdetail in CLI und lokaler UI. Speichere einen
   beschränkten letzten bekannten Stand. Unterscheide beobachtete Abwesenheit,
   eingeschränkte Sicht, veraltete Daten und nicht erreichbare Endpunkte.
   Exponiere Windows-/Linux-Gastdetails nur aus tatsächlich verfügbaren
   Quellen und kennzeichne Gastagent-Daten als solche.
3. Prüfe API-Dialekt und Rechte mit einer konkreten Versionsmatrix.
   Berücksichtige API-Ratenbegrenzung, fehlerhafte Payloads,
   Zertifikatswechsel nach bestätigter Rotation und den Neustart eines
   Agenten während einer Abfrage.

**Check/done**: Echte PVE-Quelle mit QEMU und LXC. Vergleich des Inventars
mit PVE, korrekte Angaben für PVE-Netz und Storage, temporärer Rechteentzug
und Fehlersimulation. Ein Gast außerhalb des Lesebereichs bleibt aus
Inventar und Auswertungen ausgeblendet.

## PX03 — Gast-Lebenszyklus und Provisionierung

**Voraussetzung:** PX02. **Einstieg:** registrierte Executor-Aktionen,
Ziel-Locks, Jobs und revisionsgebundene Freigabe aus RC1.

1. Biete Start, geordnetes Herunterfahren und Neustart bestehender freigegebener
   Gäste an. Verknüpfe Plan und Bestätigung mit Gastgeneration, Ist-Zustand,
   Richtlinie und Ablauf. Der zielgebundene Executor hält ein getrenntes
   PVE-Schreibtoken, prüft den lokalen Sicherheitsrahmen und verwendet nur
   registrierte API-Aktionen und erlaubte IDs. Native HA-Gäste erhalten die
   späteren PH02-Aktionen.
2. Lege QEMU-Gäste aus einer erlaubten VM-Vorlage und LXC-Gäste aus einer
   erlaubten Container-Vorlage an. Plan und Ausführung prüfen Ziel-Pool,
   VMID, Store, Netzwerk, Limits und freigegebene Vorlagenreferenz. Bei einer
   VMID-Kollision entscheidet PVE über die Anlage; die Ausführung meldet den
   Konflikt. Vorlage und Ziel sind über konkrete IDs gebunden.
3. Journalisiere den Auftrag vor dem API-Aufruf. Verknüpfe einen
   zurückgegebenen PVE-Task (UPID) mit dem lokalen Job. Erfolg verlangt
   einen passenden Task-Abschluss und beobachteten Zielzustand.
   Verlorene Antwort oder Neustart beim Dispatch führen zu einem
   abzugleichenden Zustand. Nach einem Timeout erfolgt kein erneuter
   Schreibaufruf auf Verdacht. Vorhandene Gäste und Teilanlagen erfordern
   einen expliziten Abgleich.

**Check/done**: Auf PVE je einen Test-QEMU- und Test-LXC-Gast anlegen und
durch die unterstützten Zustände führen. Prüfen: Berechtigungsablehnung,
veralterte Freigabe, belegte VMID, verlorene Antwort und wiederholter
Auftrag ohne zweite native Ausführung. Snapshot-Löschung, Gastlöschung,
erzwungenes Ausschalten und freie API-Kommandos liegen außerhalb der Karte.

## PH01 — HA-Inventar und Eignungsprüfung

**Voraussetzung:** FL03 und M11-Backup-Pfad für die HA-Testgäste.
**Einstieg:** PX02, Infrastrukturinventar, Backup-Katalog aus BK10.

1. Lies aus einem vorbereiteten PVE-Cluster Mitglieder, Quorum, Clusterzustand,
   HA-Ressourcen, Platzierungsregeln, laufende Migrationen und verfügbare
   native Statusinformationen zu Fencing. Oberflächenansicht und
   Auftragsfreigabe verwenden dieselbe aktuelle Zustandsprojektion.
2. Prüfe je Gast die erlaubten Zielknoten, Kapazität, gemeinsamen Datastores
   oder frische unterstützte Replikation, Netz-/Bridge-/VLAN-Zuordnung,
   QEMU-CPU-Kompatibilität und lokale Bindungen wie Passthrough, Mounts
   oder Geräte. Die Vorschau erläutert Abweichungen und trennt geplante
   Migration von ungeplantem Wiederanlauf.
3. Lege ein nachgewiesenes Storage- und Fencing-Profil für die drei NUCs fest.
   Prüfe vorhandenen gemeinsamen Storage für einen Hostausfall. Alternativ
   prüfe lokale ZFS-Replikation mit ausdrücklich akzeptiertem RPO und belegtem
   Replikationsziel. Dokumentiere für das gewählte Profil die gemeinsame
   Storage- und Netzabhängigkeit und bei asynchroner Replikation den letzten
   bestätigten Replikationsstand. Ein unbelegtes Merkmal sperrt die darauf
   angewiesene Aktion.

**Check/done**: Drei-Knoten-PVE-Inventar mit freigegebenen VM- und LXC-Tests.
Fehlendes Quorum, nicht erreichbarer Store, veraltete Replikation und ein
lokal gebundener Testgast sind in den Vorbedingungen sichtbar und verhindern
jeweils die unzulässige HA-Aktion.

## PH02 — HA-Aktionen und geplante Node-Wartung

**Voraussetzung:** PH01. **Einstieg:** PX03 und RC1-Wartungsfenster.

1. Registriere die durch das unterstützte PVE-Release angebotenen Aktionen zur
   HA-Aufnahme eines freigegebenen Gasts und zur gewünschten HA-Start-/Stopp-
   Einstellung. Verlange die PH01-Eignung, einen gültigen Backup-Nachweis
   nach Policy, Ziel-Lock, aktuelle Cluster-Daten und Operatorfreigabe.
   PVE führt die HA-Entscheidung aus.
2. Erzeuge einen Wartungsplan für genau einen PVE-Knoten mit Gastliste,
   Zielknoten, möglichen Unterbrechungen, Zeitfenster und Restkapazität.
   Verwende unterstützte native Wartungs-/Relocation-Aktionen. Zeige je
   Gast, ob Live-Migration verfügbar ist oder ein Stopp/Wiederanlauf
   vorgesehen ist. Der Betreiber bestätigt geplante Unterbrechungen.
3. Warte auf native Tasks und beobachtete Platzierung. Bei Teilfehlern bleibt
   der Plan mit den erreichten Zuständen erhalten. Nach Ende der Wartung
   erfolgt die Rückkehr gemäß PVE-Policy; ein Rückzug von Gästen wird als
   neue geplante Aktion behandelt. Deaktiviere den konkurrierenden
   PX03-Schreibpfad für native HA-Gäste.

**Check/done**: Native HA-Aufnahme und geplante Wartung eines Knotens mit
je einem VM- und LXC-Testgast. PVE- und Steward-Ansicht stimmen bei Task,
Zielknoten und Gaststatus überein. Veralteter Plan, unzureichende
Zielkapazität und ein blockierter Gast lösen keinen weiteren Schritt aus.

## PH03 — Ungeplanter PVE-Ausfall und Rückkehr

**Voraussetzung:** PH02, autorisierte physische Testtopologie.
**Einstieg:** ausgeführte PVE-Wartungsjobs, Ereignisprojektion und BK11.

1. Prüfe die in PH01 definierte Fencing-Kette bei Ausfall eines PVE-Hosts.
   Erfasse PVE-Quorum, Fencing-Ereignis, Gastplatzierung, Wiederanlaufzeit
   und Nutzdaten-Lesetest. PVE entscheidet über den neuen Start, und
   OpsTend verfolgt den Übergang in der Oberfläche.
2. Prüfe eine Netzpartition mit Mehrheits- und Minderheitsseite, gefolgt
   von Quorumverlust oder fehlendem Storage im Testprofil. Die Steuerung
   zeigt die beobachtete Ursache, sperrt passende Schreibpfade und gleicht
   laufende native Tasks nach Erholung ab. Ein nicht wieder anlaufbarer
   Gast erhält einen expliziten Hinweis auf den vorbereiteten Restore-Pfad.
3. Bringe den ausgefallenen Knoten zurück. Prüfe, dass Gäste und deren
   beobachtete Instanz eindeutig bleiben und dass eine Rückkehr nicht
   eigenmächtig einen durch OpsTend veranlassten Gaststart auslöst.
   Abweichende RPO/RTO-Werte werden mit Ursache erfasst.

**Check/done**: Physische Fencing-/Quorum-Abnahme mit aufgezeichneten
PVE-Ereignissen, Wiederanlauf je eines Test-VM- und Test-LXC-Gasts,
Nutzdatenprüfung und Ausschluss zweier gleichzeitig aktiver Instanzen
des jeweiligen Gasts. Die Gate-Ergebnisse gelten für das getestete
Storage- und Fencing-Profil.
