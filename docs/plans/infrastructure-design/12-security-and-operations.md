# 12 · Vertrauensgrenzen, Audit und Betriebsstörungen

Vertieft die Sicherheitsverträge von PX01–PX03, FL01–FL03, BK09,
IN01–IN03 und CP01–CP03. Stand der Recherche 2026-11-24.
Das lokale [Executor-Modell aus ADR 0001](../../adr/0001-architecture.md)
bleibt die erste Grenze. Die Flotte fügt gegenseitig authentisierte
Netzpfade und nachweisbare Zuständigkeiten hinzu.

## Rollen und Durchsetzungsorte

| Sender oder Rolle | Eigener erlaubter Zugriff | Prüfpunkt |
|---|---|---|
| Operator / UI / CLI | Autorisierte Sicht, gebundene Vorschau, bestätigte Aktion | Authentisierte Sitzung, Rollen-/Ressourcen-Scope, Plan-Digest, Zeitfenster und aktuelle Zielgeneration |
| Flotten-Koordinator | Policies und Jobs planen sowie Claims beantragen | Aktuelle Autorität, revisionsgebundener Zustand, Budget, Idempotenz und Freigabe |
| Host-/Quellbeobachter | Nur zugeordnetes Inventar, Messungen und Quittungen veröffentlichen | Individueller Source-Scope, Zeit, Reihenfolge, Schema und Payload-Limits |
| Ziel-Executor | Registrierte Actions mit eng gescopten Credentials oder lokaler Hostidentität | Lokale Sicherheitsgrenze, aktuelles Rollenrecht, Kill Switch, Vorbedingungen, Sperre und resultierende Wirkung |
| Backup-Schreiber, -prüfer und Retention | Jeweils konkreter Repository-/Namespace-Scope und verschiedene Rechte | Datensichere Zuordnung, Schlüssel-ID, Prune-Verantwortung und unabhängiger Prüfnachweis |
| Quorum-Mitglied | Repliziert autoritativen KV-Zustand. Dienste erhalten nur Rollen und benötigte Präfixe. | Private mTLS-Kommunikation, getrennte Admin-Credentials, Snapshot- und Restore-Autorität |

Der Zugriff auf ein Netzsegment ergibt keine Verwaltungsberechtigung.
Agentenidentität und Benutzeridentität sind eigene Sicherheitskontexte.
Rollenentscheidung, Transportvertrauen und Bindung an eine konkrete
native Ressource werden separat geprüft. Externe Linux-Hosts
bekommen dieselben fachlichen Rollen im Rahmen ihres Zielprofils.
[NIST Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final) ·
[OpsTend Executor-Erweiterung](../../extending.md)

## TLS- und Credential-Optionen

| Option | Geeignet für | Grenze |
|---|---|---|
| CA-validierte Gegenstelle mit erwartetem Namen | Regelmäßige Zertifikatserneuerung für private oder vertrauenswürdig ausgerollte Endpunkte | Sorgfältige Zuordnung zu registriertem Host und gewünschtem Vertrauensbündel. TLS allein beweist keine PVE-Instanzzugehörigkeit. |
| Fingerprint bestätigter PVE-Gegenstelle | Selbstsigniertes Zertifikat und kleiner administrativer Scope | Bei Erneuerung separat bestätigen. Geplantes Überlappungsfenster nur mit vorab bestätigtem Material. |
| Gegenseitig authentisierte Agentenverbindung | Registrierte Ziele und private Site-Transportwege | Identität pro Agent, Zertifikatszweck, Ablauf, Rotation und Widerrufsbeobachtung. Die autoritative ACL bleibt zusätzlich wirksam. |
| Individuelles kurzlebiges PVE-/PBS-Token nach Aufgabe | Zugriff auf native Backends mit minimaler Wirkung | Jeder Token-Wert bleibt beim zuständigen Worker. Credentials für Prüfung und Aufbewahrung haben eigene Lebensdauern und Rechte. |
| Spätere externe Identität über OIDC und Zertifikatsbindung | Größere Administration oder getrennte Trust Domains | Menschliche Sitzung und Agentencredential haben eigene Freigabe- und Widerrufsmodelle. Ein höherer Standardumfang braucht eigene Abnahme. |

[TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) ·
[PKIX-Zertifikatprofil](https://www.rfc-editor.org/rfc/rfc5280.html) ·
[OAuth mTLS und gebundene Tokens](https://www.rfc-editor.org/rfc/rfc8705.html) ·
[PDM Zertifikatsrotation](https://pdm.proxmox.com/docs/remotes.html#connection-and-certificate-troubleshooting)

Zertifikats- und Rollendrehung werden gemeinsam getestet. Der
Agent validiert die Gegenstelle und den aktuellen Stand des Vertrauensbundles.
Ein neuer Zertifikatspfad kann erst nach belegter Zuordnung einen
bestehenden Scope nutzen. Während Pins oder Rollen ungeklärt sind,
liefert die UI den letzten zulässigen, datierten Zustand und
verweigert neue Schreiberlaubnis. Native Tasks aus der alten
Credential-Zeit werden mit ihrer echten Ausführungsidentität
abgeglichen.

## Ereignisse, Beweis und Aufbewahrung

Ein Audit-Event enthält Ereignis-ID, Actor und Rolle, Ziel- und
Ressourcengeneration, zuständigen Executor, Richtlinien- und
Plan-ID, genehmigte Operation, Zeitpunkt und gegebenenfalls
native UPID/Backup-Quittung. Jobreceipt und beobachteter Zustand
bleiben getrennte Nachweise. Die vorhandene lokale Hash-Ketten-
Architektur ist das Vorbild für vertrauenswürdige Reihenfolge.
Ein unabhängiger Export oder überprüfbarer Anker eignet sich für
höheren Nachweisbedarf. Ein lokaler Hash ohne externen Anker
belegt gegenüber einem vollständig kompromittierten Host keinen
unabhängigen Verlauf.

Rohe Backend-Logs bleiben in ihrem Scope. Normalisierte
Fehlercodes und gekürzte Auditdaten dürfen in die Oberfläche.
Secrets, vollständige Zugriffsheader, private URLs mit Tokens,
nicht freigegebene Serialnummern, private Netzwerk- oder
Credential-Werte gehen nicht in Reports, Browserbundles,
Backup-Metadaten oder Telemetrie. Aufbewahrung folgt dem
Datentyp. Ein Audit-Export braucht gesonderte Scope- und
Redaktionsregeln. [OpsTend Architektur](../../architecture.md)

## Störfälle und kontrollierte Wiederaufnahme

| Situation | Reaktion des Systems | Bereits zugeordnete Abnahme |
|---|---|---|
| Verlorene oder kompromittierte Agentenidentität | Registry-Generation widerrufen, Schreibaktionen sperren, anschließend mit bestätigter Identität neu aufnehmen und native Jobs abgleichen. | FL01–FL03 |
| Koordinator ohne Quorum oder neuer lokaler Head | Keine neuen freigegebenen Dispatch-Claims. Gehaltene Claims bleiben bis terminalem Abgleich aktiv; Anzeige mit Frischekennzeichnung. | CP01–CP03 |
| Falscher Zielendpunkt oder unerwartete Zertifikatsänderung | Verbindung im betroffenen Scope abbrechen. Unabhängige Quellen weiterführen und bestätigten Wechsel ermöglichen. | PX02, FL01 |
| Backup-Repository kompromittiert oder Zugang nicht mehr verfügbar | Snapshot-Sicht und unabhängige Copy-/Restore-Belege getrennt halten. Recovery nutzt einen tatsächlich qualifizierten alternativen Datenpfad. | BK09–BK11 |
| Externe manuelle PVE-Aktion oder ein nativer Zeitplan | Native Wirkung und Actor soweit verfügbar importieren. Schreibende Steward-Operationen prüfen ihre aktuellen Voraussetzungen erneut. | PX03, FL03, PH02 |
| Maßnahme während Wartung oder Notfall | Bestehende gesondert freigegebene Operatorregeln anwenden. Das System zeigt Auslöser, Wirkung und erforderlichen nächsten Abgleich. | FL03, PH02, IR01 |

**Vertrauensgrenze.** Ein vollständiger Root-Kompromiss einer
Zielmaschine kann ihren Credential- und Beobachtungspfad betreffen.
Der Flottenscope begrenzt die erteilte Reichweite. Er schafft keine
Garantie für das physisch kompromittierte Ziel. Für einen
Vorfall werden Rollen widerrufen, Ausgabepfade geprüft und
Ursprungszustände aus geeigneten Quellen wieder validiert.
