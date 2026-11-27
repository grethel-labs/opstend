# 05 · Ubuntu-vServer, NAS, Geräte und der KI-Host

Karten IN01–IN02 und NX01–NX04 in [Infrastruktur](../infrastructure.md),
BK09 für Storage-Ziele und CP03 für Ressourcenreserven. Zum lokalen
Referenzinventar gehören acht PVE-Hosts, ein Ubuntu-Teilnehmer, ein
Cloud Gateway mit Switch und das Pi-NAS. Zwei externe Ubuntu-Hosts
gehören über ihre Standort- und Berechtigungskontexte zur Flotte.

## Vergleich der Anschlussarten

| Anschluss | Daten und Bedienung | Betriebsaufwand | Geeignet für |
|---|---|---|---|
| Registrierter Linux-Agent | Inventar, Heartbeats, Container, Auftragsquittungen und registrierte Executor-Aktionen | Lokale Units, kurze Zertifikatslaufzeit, Rotation und definierte Ressourcen | Ubuntu 26.04 LTS mit rootless Podman und Quadlet als Referenz. Debian, Fedora und Arch brauchen eigene Profilabnahmen. |
| UniFi Network API | Adoptierte Geräte und beobachtete Clients, Netze, Port- und Verbindungsdaten je getesteter Version | Getrennte Lese- und Schreibrollen, bestätigtes Cloud-Gateway-/Switchprofil | IN02 liest das Inventar. NX04 qualifiziert eine reversible Änderung. [Offizielle UniFi API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API) |
| Vorhandener HTTPS-Metrikendpoint | Zum Beispiel Linux- und Dateisystem-Metriken oder eine HTTP-Gesundheitsprobe | Authentisierung, Egress-Grenze, Label- und Größenbudget. Der Endpoint misst nur seinen eigenen Scope. | NAS, vorhandene Exporter, extern beobachtete Dienste. [Prometheus Node Exporter](https://prometheus.io/docs/guides/node-exporter/) |
| SNMPv3 mit eingeschränktem Lesebereich | Geräteidentität, Interfaces und unterstützte Zähler | Gerät, Algorithmen, erwartete OIDs, Engine-/Zeitstatus und Zugang müssen passen. | Ausgewählte verwaltete Switches, USV oder vergleichbare Geräte. Kein generischer SNMP-Manager. [SNMPv3 USM](https://www.rfc-editor.org/rfc/rfc3414.html) · [SNMP AES](https://www.rfc-editor.org/rfc/rfc3826.html) |
| Registrierter TCP- oder HTTPS-Dienstcheck | Geringe Eingriffstiefe, beobachteter Netzwerkpfad, Antwortzeit und eindeutige Grenze seiner Aussage | Keine Einsicht in tatsächliche Datenträger, Hintergrundprozesse oder alle Schnittstellen | Dienste ohne Agent. Check läuft am jeweils registrierten Netzstandort. |
| Allgemeiner SSH- oder Fernbefehlskanal | Große Reichweite bei Hostadministration | Schwer auf fachliche Wirkung, Identität und Parameter begrenzbar | Betreiberwartung bleibt außerhalb des Steward-Gerätedienstes. Der Linux-Agent benutzt registrierte Executor-Aktionen. |

Ein Ziel kann mehrere Quellen haben. Das Pi-NAS kann als Gerät mit
HTTPS-Erreichbarkeit und zugleich als Speicherquelle einer Freigabe
registriert sein. Labels für Geräte und Standorte werden durch die
Betreiberzuordnung belegt. Beobachtete Clients aus einer zugelassenen
Quelle sind auffindbar und werden erst nach bestätigter Identität zur
Verwaltung aufgenommen. Aktionen prüfen die aktuelle Abdeckung.

## Externe Ubuntu-26.04-LTS-Hosts

Ubuntu Server 26.04 LTS ist bereits das primäre Steward-OS-Profil.
Unterstützung für den konkreten vServer folgt aus Architektur,
Kernel, Virtualisierungsmodus, systemd, erreichbarem Privatnetz und den
für die gewählte Rolle nötigen Capabilities. Für einen Beobachtungsagenten
ist ein freier VM- oder Container-Builder irrelevant. Privilegierte
Workload-Funktionen prüfen cgroup-Delegation, erlaubte User Namespaces,
Mount- und Netzwerkverhalten gesondert. Der Gastanbieter kann einzelne
Fähigkeiten einschränken. Ubuntu dokumentiert den Wegfall seiner
cgroup-v1-Kompatibilität in systemd 259.
[Steward Support-Matrix](../../support-matrix.md) ·
[Ubuntu 26.04 LTS Systemänderungen](https://documentation.ubuntu.com/release-notes/26.04/changes-since-previous-interim/)

| Vorgeschlagene Rolle | Erwartete Daten oder Funktion | Freigabekriterium |
|---|---|---|
| Externer Linux-Agent auf beiden vServern | Version, freigegebene CPU/RAM/FS-Werte, registrierte Dienste, letzte angewandte Revision und ggf. lokale Jobs | Ausgehendes mTLS, Rollenrotation, versionsgebundene Capabilities, begrenzte Queue und Wiederaufnahme nach Trennung |
| VPN-Host, HTTPS-Proxy und Fernzugangsportal auf einem vServer | Getrennt aktivierbare Rollen mit Tunnel, veröffentlichter Website und berechtigtem Browserzugang | Automatische Tunnelaufnahme, extern bestätigte Website sowie gesonderter Portal-Login und Widerruf nach NX02–NX03 |
| Externer Beobachter auf einem vServer | Beobachtet ausdrücklich registrierte, aus dieser Site erreichbare Dienste | Quelle und Ort im Befund. Ein WAN-Fehler darf lokale Erreichbarkeit und Anwendungsgesundheit nicht pauschal auf Fehler setzen. |
| Externe Restic-Rolle auf geeignetem vServer | Aufnahme freigegebener Repository-Daten über den vorhandenen HTTPS-Pfad | Speicher und Quotas, direkte und wiederanlaufbare Restore-Übertragung, TLS, getrennte Betreiber- und Uploadrechte. [Backup und Restore](03-backup-and-recovery.md) |
| Ein späterer privater Zugangspunkt | Wiedererreichbarer Betriebszugang zur autoritativen Verwaltung | Eigene Freigabe für ACL, TLS-Endpunkt, Audit, Erreichbarkeit und Anbieterbedingungen. Bei Verlust des Heimstandorts entsteht daraus keine neue Schreibautorität. |

Beide Server besitzen je 8 GB RAM und 4 vCPU. Das Beispiel legt Rollen
nach Fähigkeit und Reserve fest. Es benötigt keine Annahme über
Verschachtelung, Systemplattenplatz oder unterschiedliche Anbieter.
Der verwaltete Tunnel nutzt WireGuard im Referenzprofil. Der private
Agenten- und Bootstrap-Zugriff hat einen separat qualifizierten Pfad.
App-Identität und aufgenommener Ziel-Scope gelten für beide.

## Pi-NAS als Gerät, Netzfreigabe und Datenträger

- **Physische Ebene.** Modell, OS, Anschlusstyp der beiden NVMe,
  Dateisystem, tatsächlicher Mount, Strom-/Netzpfad, Fehler- und
  Temperaturwerte soweit verfügbar. Zwei belegte NVMe-Slots werden
  inventarisiert. Ihre Redundanz ist eine Eigenschaft des belegten
  Layouts, beispielsweise eines expliziten Mirrors.
  [Raspberry Pi M.2-Dokumentation](https://github.com/raspberrypi/documentation/blob/master/documentation/asciidoc/accessories/m2-hat-plus/about.adoc)
- **Freigabeebene.** Das tatsächlich genutzte Protokoll, Scope,
  Zuordnung und belegte Kapazität je
  registrierter Freigabe. NFS und SMB haben unterschiedliche
  Authentisierung, Locking und Clientprofile. Linux-/PVE-Dateiziele
  können NFS nutzen, gemischte Clientlandschaften SMB. Ein Check eines
  TCP-Ports ist getrennt von der autorisierten Leseprobe und vom
  Space-Report. [NFSv4.2](https://www.rfc-editor.org/rfc/rfc7862.html) ·
  [SMB 2/3 Spezifikation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- **Schutzebene.** Das Backend eines Exports, letzte erfolgreiche
  Nutzung, vorhandenes externes Backup und letzte Restore-Evidenz
  sind eigenständige Graphkanten beziehungsweise Ereignisse. Der
  konkrete Restic- oder PBS-Kopierpfad entscheidet über externe
  Recovery. [Gemeinsamer Backup-Katalog](03-backup-and-recovery.md)

Ein Ausfall des Pi muss daher als „NAS nicht erreichbar,
Freigabe möglicherweise betroffen“ erscheinen. Lokale Bootsicherheit
der Steward-Quorum-Instanzen und HA-Gast-Disks werden im Referenzprofil
über separat qualifizierte Speicherpfade geprüft. Ein vorhandener
lokaler NAS-Dienst braucht für diese Beobachtung keine vollständige
Steward-Installation auf Arm64. Native Linux-Executor-Unterstützung
auf einem Pi ist ein eigenständiges Supportprofil.

## Datenverkehr, Überwachung und Isolierung

1. Agenten verbinden sich zum privaten Verwaltungsendpunkt und übernehmen
   nur eindeutig adressierte, autorisierte Nachrichten. Check-Frische
   und Credential-Frische sind getrennte Zeitgrenzen. Wiedereinwahl
   meldet letzte angewandte Revision und bestätigten Beobachtungscursor.
2. Ein Connector im Zielnetz löst registrierte Adressen auf und benutzt
   ausschließlich den für Ziel-ID und Profil hinterlegten Transport.
   Ein URL-Feld in einem Agenten-Report eröffnet keinen neuen Egress.
   Erlaubte Ports, Header, Zertifikate und Antwortgrenzen folgen der
   Adapterregistrierung. Keine breitflächige automatische Geräteaufnahme.
3. Der Beobachtungsadapter führt freigegebene SNMP-Abfragen nur lesend
   aus. Er meldet Protokoll- oder Authentisierungsfehler getrennt von
   einer nicht erreichbaren Gegenstelle. Zulässige OIDs, Einheiten,
   Zeitbudgets und Firmwareeinschränkungen gehören zum Geräteprofil.
4. Das Gerät erhält eine stabile ID. Netzwerkwechsel und
   Credential-Rotation erfordern belegte Kontinuität. Der Zeitstempel
   der Messung und der verwendete Standort bleiben beim Befund. Ein
   gecachter Erfolg kann als veraltet angezeigt werden und gilt nicht
   als aktuelle Gesundheit.

## Beelink GTR9 Pro als optionale KI-Platzierung

Beelink dokumentiert für das GTR9-Pro-Modell einen Ryzen AI Max+ 395
mit integrierter Grafik. Verifizierte Firmware, tatsächlich nutzbare
RAM- und Gerätespeicheranteile, PVE-Kernel, Gastprofil, Treiber,
Container-Runtime und konkretes Inferenz-Backend bestimmen die
Ausführbarkeit. Herstellerkompatibilität auf nativem Linux
belegt weder LXC-Gerätefreigabe noch VM-Passthrough. Der Scope
„KI verfügbar“ entsteht erst durch einen erfolgreichen Profiltest.
[Beelink GTR9 Pro](https://www.bee-link.com/products/beelink-gtr9-pro-amd-ryzen-ai-max-395) ·
[AMD ROCm Kompatibilitätsmatrix](https://rocm.docs.amd.com/en/docs-7.14.0/compatibility/compatibility-matrix.html) ·
[Ollama Hardware Support](https://docs.ollama.com/gpu)

| Variante | Isolation und Aufwand | Kriterium für weitere Umsetzung |
|---|---|---|
| Inferenzdienst im separaten unterstützten Linux-Gast, zunächst CPU | Einfacher Referenz-Nachweis für API, Limits, Verbrauch und Datenfluss. CPU-Leistung hängt von Modell und Last ab. | Reale Health-Probe, reproduzierbarer kleiner Modellsatz, Zeit-/RAM-Grenzen aus dem Inference-Vertrag. |
| Hardwarebeschleunigung im begrenzten LXC | Direkter Bezug zum Host-Treiber, Gerätedateien und erlaubte Containerprivilegien. Lokale Hardwarezuordnung. | Nur mit kleinem verifiziertem Geräteprofil. Treiber-/ABI-Passung, minimale Device-Rechte, isolierter Modell-Cache, Neustart- und Abbruchtest. |
| Dedizierte VM mit geeigneter Hardware-Zuweisung | Eigene Gastumgebung und stärkere Trennung bei erhöhtem Betriebsaufwand. Eignung hängt vom tatsächlichen Gerät und Plattformprofil ab. | Nachweis für konkrete Host-Hardware, Treiber, Gerätezuordnung, Daten- und Wiederherstellungspfad. |

Das Profil gibt Mindest- und Maximalbedarf für reservierten RAM,
CPU, Platz für Modellartefakte und den konkreten lokalen Slot an. Die
Platzierung verrechnet diese Reserve mit der gemessenen Hostkapazität.
Ein geplanter Test weist nach, dass Steward-Rollen einem überbuchten
KI-Host ausweichen können. Bei einem Ausfall des KI-Hosts bleibt die
deterministische Verwaltung funktionsfähig. Das KI-Profil folgt dem
bestehenden [Inference-Vertrag](../../adr/0007-inference-contract.md)
und dem [Onboarding](../../adr/0008-ai-onboarding-and-model-selection.md).

**Abnahme.** IN01 prüft getrennte Linux-Anschlüsse und den
Podman-Lifecycle. IN02 vergleicht UniFi-Netzbeziehungen und NAS-Daten
mit den realen Quellen. NX02–NX04 prüfen Tunnel, Veröffentlichung,
Portal und Netzänderung. IR01 verbindet die Pfade mit realer
Platzierung, Reserven und WAN-/NAS-Verlust. Hardwarebeschleunigte
Inferenz erhält eine eigene Abnahme.
