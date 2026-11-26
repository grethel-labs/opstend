# Recherche und Architektur nach RC1

Stand 2026-11-24. Die Themenakten ergänzen die
[Meilensteine M9–M15](../../post-rc1.md) und deren 20 Karten. Sie
enthalten dokumentierte Alternativen, Entscheidungsvorschläge,
Betriebsverträge und konkrete Belegfragen. Die bestehenden
Karten behalten Reihenfolge, Umfang und Abnahmekriterien.
Die [Abnahme](08-delivery-and-iterations.md) trennt Quellenbefunde,
lokale Vertragsprüfungen und reale Host-/Provider-Evidenz.

## Lesereihenfolge

| Nr. | Thema | Schwerpunkt und verantwortliche Karten |
|---|---|---|
| 01 | [Proxmox nativ](01-proxmox-native.md) | Installationsformen, PVE-API, Task-Semantik und Abgrenzung zu PDM, Ansible und OpenTofu · PX01–PX03 |
| 02 | [Flotte und Vertrauen](02-fleet-and-trust.md) | Ressourcenidentität, Revisionen, Ownership, Enrollment und Auftragsfreigabe · FL01–FL03 |
| 03 | [Sicherung und Wiederherstellung](03-backup-and-recovery.md) | PBS/Restic/NAS, Offsite-Sync und Speicher, Konsistenz, Kapazität und geprüfte Restores · BK09–BK11 |
| 04 | [Proxmox HA und Speicher](04-proxmox-ha-and-storage.md) | 3- und 7-Knoten-Quorum, ZFS, Shared Storage, Ceph, Migration und Fencing · PH01–PH03 |
| 05 | [Linux, Geräte, NAS und KI](05-linux-devices-and-ai.md) | Ubuntu-vServer, Pi-Anschluss, Protokolle, Ressourcenreserven und Inferenz auf dem Beelink · IN01–IN02 und CP03 |
| 06 | [Dashboard und Topologie](06-observability-and-ui.md) | Herkunft der Graphkanten, Rechte, Telemetrie, Browserbedienung · IN03 |
| 07 | [OpsTend HA](07-steward-ha.md) | SQLite und Quorum-Optionen, automatische Rollenwahl, Hot-Standbys, externe Schreibwirkungen und Wiederaufbau · CP01–CP03 |
| 08 | [Abnahme bis RC2](08-delivery-and-iterations.md) | Messbare Stände, Upgrade, Störfälle, RPO/RTO und signiertes Release · PX01–IR02 |
| 09 | [Referenzprofil und Dimensionierung](09-reference-profile.md) | Gemischte Beispielkonfiguration, alternative Topologien, Hardware-Belegliste und Ausfallmatrix · IR01 |
| 10 | [Fünf Ausbaustufen nach RC2](10-follow-up-iterations.md) | Betrieb, zusätzliche Adapter, Lifecycle, Standort-Recovery und weitere dynamische Rollen |
| 11 | [Vergleich vorhandener Plattformen](11-platform-comparison.md) | PDM, Cockpit, Zabbix, NetBox, AWX, OpenTofu, Xen Orchestra, Harvester, Incus und Observability |
| 12 | [Vertrauensgrenzen und Betrieb](12-security-and-operations.md) | Rollen, TLS, Credentialrotation, Audit und Reaktion auf Störungen · PX01–CP03 |

## Entscheidungen mit praktischen Prüfpunkten

| Frage | Vorläufige Richtung | Was die Entscheidung abschließt |
|---|---|---|
| Welche PVE-Versionen kann OpsTend schreiben? | Ein geprüfter amd64-PVE-Releasebereich und nur registrierte Methoden. Ein neuer Dialekt kann mit eingeschränkten Fähigkeiten aufgenommen werden. | PX01–PX03 testen Paket, API, ACL, TLS, Tasks und Readback am tatsächlichen Versionsstand. |
| Wie verbinden sich lokale und externe Instanzen? | Ein Flottenkopf, verifizierte Instanz-/Host-/Gast-IDs und ausgehende Agentenverbindungen. API-only als eigener Anschlussmodus. | FL01–FL03 prüfen Reconnect, Teilanwendung, Scope und Übernahme vorhandener Writer. |
| Wo liegen Sicherungen auf dem Referenzaufbau? | Pi-Dateispeicher lokal, Gast-Sicherungen über verifiziertes PBS, Anwendungsdaten über Restic mit möglichem externen Ubuntu-Ziel. | BK09–BK11 belegen Kapazität, unabhängige Kopien, Schlüssel und echte Nutzdatenwiederherstellung. |
| Welches Storage-Profil ermöglicht PVE-HA? | Ein vorhandener qualifizierter Shared Store oder lokales ZFS mit akzeptiertem RPO. PVE entscheidet über Wiederanlauf. | PH01–PH03 prüfen Geräte, Kapazität nach Einzelausfall, nativen Zustand und tatsächliches Fencing. |
| Was bedeutet eine Verbindung im Dashboard? | Kante mit eindeutiger Semantik, Zeit, Scope und Beleg. Graph und Liste nutzen dieselbe gefilterte Projektion. | IN03 vergleicht reale Stichproben und prüft indirekte Informationskanäle sowie veraltete Quellen. |
| Wie übernimmt ein Ersatzdienst? | Quorum bestätigt den Rolleninhaber. Jobs mit bereits beanspruchter Außenwirkung behalten ihre Sperren. | CP01–CP03 prüfen Quorumverlust, alte Rolle, verlorene Antwort und Fortschritt unabhängiger Ziele. |
| Was verhindert Abhängigkeit von genau einer Topologie? | Fähigkeitsverträge und optionale Rollen. Testprofile beginnen beim Einzelhost und enthalten heterogene Flotten. | IR01–IR02 prüfen die gemischte Referenz und halten Installations-/Supportvarianten getrennt. |

**Verwendung.** Vom [Meilenstein](../../post-rc1.md) zur zuständigen
Karte wechseln und nur die relevante Themenakte sowie deren Quellen
öffnen. Bei dynamischen Produkt- oder API-Aussagen den Release-Stand
bei Kartenbeginn erneut prüfen. Messwerte und private Receipts gehören
in die dokumentierte Abnahmespur. Betreiberparameter und Zugangsdaten
bleiben außerhalb der versionierten Dokumente.
