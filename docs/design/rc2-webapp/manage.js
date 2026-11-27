(() => {
  const views = window.opstendViews ??= {};
  const { t } = window.opstendLocale;
  const jobs = [
    {
      id: 'sensorik', serviceId: 'sensorik', host: 'host-b', time: '14:21:08', title: 'Sensorik neu gestartet',
      type: 'Selbstheilung', status: 'Wird geprüft', tone: 'active',
      target: 'Podman · Sensorik', actor: 'OpsTend Controller',
      context: 'Sensorik meldete drei fehlgeschlagene Healthchecks. Die Flottenrichtlinie erlaubt einen Neustart auf host-b.',
      outcome: 'Neustart ausgeführt', verification: 'Health-Nachprüfung läuft · seit 14:21:08',
      attention: {
        kind: 'incident',
        title: 'Sensorik antwortete nicht',
        impact: 'Drei Healthchecks sind fehlgeschlagen. Der Dienst wurde neu gestartet.',
        status: 'Zorec prüft den Wiederanlauf',
        action: 'Prüfung verfolgen',
      },
      events: [
        ['14:20:41', 'Störung erkannt', 'Dritter fehlgeschlagener Healthcheck für Sensorik.'],
        ['14:20:44', 'Richtlinie geprüft', 'Neustart war vom Betreiber vorab erlaubt. Die Wartezeit war abgelaufen.'],
        ['14:21:08', 'Neustart ausgeführt', 'Der Executor meldete den Podman-Dienst wieder als laufend.'],
        ['Läuft', 'Health-Nachprüfung', 'Der Controller prüft, ob Sensorik wieder über den registrierten Pfad antwortet.'],
      ],
    },
    {
      id: 'route', serviceId: 'medien', host: 'edge-01', relatedHost: 'nuc-a', linkId: 'edge-tunnel',
      time: '14:18:34', title: 'HTTPS-Freigabe für Medien',
      type: 'Netzwerkänderung', status: 'Wartet auf Freigabe', tone: 'warn',
      target: 'HTTPS-Proxy · Medien', actor: 'Betreiberin',
      context: 'Der Entwurf verbindet den externen HTTPS-Proxy über den VPN-Pfad mit dem registrierten Webdienst Medien.',
      outcome: 'Freigabe steht aus', verification: 'Entwurf · keine Ausführung',
      attention: {
        kind: 'decision',
        title: 'Medien extern erreichbar machen',
        impact: 'Die HTTPS-Adresse würde Webzugriffe von außen zu Medien auf nuc-a leiten.',
        status: 'Deine Freigabe ist gefragt',
        action: 'Freigabe prüfen',
      },
      events: [
        ['14:18:19', 'Entwurf erstellt', 'Vorgeschlagenes Ziel ist der Webdienst Medien auf nuc-a.'],
        ['14:18:34', 'Interner Abruf geprüft', 'Der simulierte Prüfpunkt meldete den internen Dienst Medien als erreichbar.'],
        ['Ausstehend', 'Betreiberfreigabe', 'Die Freigabe ist an Ziel, Domain und konkreten Entwurf gebunden.'],
        ['Ausstehend', 'Externer Abruf', 'Nach der Ausführung prüft ein externer Prüfpunkt die veröffentlichte Adresse.'],
      ],
    },
    {
      id: 'entwicklung', serviceId: 'entwicklung', host: 'nuc-a', time: '13:52:19', title: 'Entwicklungs-VM gestartet',
      type: 'Gastverwaltung', status: 'Abgeschlossen', tone: 'success',
      target: 'QEMU-VM · Entwicklung', actor: 'Betreiberin',
      context: 'Der Start der Entwicklungs-VM wurde aus dem Ressourcendetail für nuc-a angefordert.',
      outcome: 'VM läuft auf nuc-a', verification: 'Gastzustand von Proxmox bestätigt · 13:52:19',
      events: [
        ['13:52:02', 'Start angefordert', 'Ziel und Berechtigung für die bestehende VM wurden geprüft.'],
        ['13:52:05', 'Proxmox-Auftrag gestartet', 'Die native Aufgaben-ID wurde dem OpsTend-Auftrag zugeordnet.'],
        ['13:52:19', 'Gastzustand bestätigt', 'Proxmox meldete die VM als laufend.'],
      ],
    },
  ];

  const jobEnglish = new Map([
    ['Sensorik neu gestartet', 'Sensorik restarted'],
    ['HTTPS-Freigabe für Medien', 'HTTPS approval for Medien'],
    ['Entwicklungs-VM gestartet', 'Entwicklung VM started'],
    ['Selbstheilung', 'Self-healing'],
    ['Netzwerkänderung', 'Network change'],
    ['Gastverwaltung', 'Guest management'],
    ['Hostwartung', 'Host maintenance'],
    ['Betreiber', 'Operator'],
    ['Betreiberin', 'Operator'],
    ['Läuft', 'In progress'],
    ['Ausstehend', 'Pending'],
    ['Abgeschlossen', 'Completed'],
    ['Wird geprüft', 'Verifying'],
    ['Wiederhergestellt', 'Recovered'],
    ['Entscheidung ausstehend', 'Decision pending'],
    ['Früherer Vorgang', 'Previous job'],
    ['Wartet auf Freigabe', 'Awaiting approval'],
    ['Freigabe steht aus', 'Approval pending'],
    ['In der Demo freigegeben', 'Approved in the demo'],
    ['Abgelehnt', 'Rejected'],
    ['Entscheidung im Browser gespeichert', 'Decision saved in this browser'],
    ['Entwurf · keine Ausführung', 'Draft · not executed'],
    ['Sensorik meldete drei fehlgeschlagene Healthchecks. Die Flottenrichtlinie erlaubt einen Neustart auf host-b.', 'Sensorik failed three health checks. Fleet policy allows a restart on host-b.'],
    ['Neustart ausgeführt', 'Restart executed'],
    ['Health-Nachprüfung läuft · seit 14:21:08', 'Follow-up health check in progress · since 14:21:08'],
    ['Störung erkannt', 'Incident detected'],
    ['Dritter fehlgeschlagener Healthcheck für Sensorik.', 'Sensorik failed its third health check.'],
    ['Richtlinie geprüft', 'Policy verified'],
    ['Neustart war vom Betreiber vorab erlaubt. Die Wartezeit war abgelaufen.', 'The operator had authorised the restart and the waiting period had elapsed.'],
    ['Der Executor meldete den Podman-Dienst wieder als laufend.', 'The executor reported the Podman service running again.'],
    ['Health-Nachprüfung', 'Follow-up health check'],
    ['Der Controller prüft, ob Sensorik wieder über den registrierten Pfad antwortet.', 'The controller checks whether Sensorik responds over the registered path again.'],
    ['Health-Nachprüfung erfolgreich', 'Follow-up health check passed'],
    ['Die simulierte Probe am registrierten Health-Pfad liefert die erwartete Antwort.', 'The simulated probe on the registered health path returned the expected response.'],
    ['Health-Nachprüfung fehlgeschlagen', 'Follow-up health check failed'],
    ['Die simulierte Probe am registrierten Health-Pfad liefert keine Antwort.', 'The simulated probe on the registered health path received no response.'],
    ['Erneute Nachprüfung angefordert', 'Another health check requested'],
    ['Der Betreiber stößt die Prüfung ohne weiteren Neustart an.', 'The operator starts another check without restarting the service again.'],
    ['Zorec hat eine Health-Nachprüfung angefordert', 'Zorec requested a follow-up health check'],
    ['Zorec nutzt die freigegebene einmalige Health-Nachprüfung am registrierten Pfad.', 'Zorec uses the approved one-time follow-up on the registered health path.'],
    ['Zorec hat eine weitere Health-Prüfung angestoßen.', 'Zorec started another health check.'],
    ['Sensorik antwortet wieder', 'Sensorik is responding again'],
    ['Simulierte Health-Nachprüfung erfolgreich', 'Simulated follow-up health check passed'],
    ['Sensorik antwortet weiterhin nicht', 'Sensorik is still unresponsive'],
    ['Simulierte Health-Nachprüfung fehlgeschlagen', 'Simulated follow-up health check failed'],
    ['Erneute Health-Nachprüfung läuft', 'Another health check is in progress'],
    ['Von Zorec angestoßene Health-Nachprüfung läuft', 'Zorec’s follow-up health check is in progress'],
    ['Die erneute Health-Nachprüfung ist fehlgeschlagen.', 'The follow-up health check failed again.'],
    ['Erneute Health-Nachprüfung', 'Another health check'],
    ['Die simulierte Probe wartet auf ein Ergebnis.', 'The simulated probe is waiting for a result.'],
    ['Den aktuellen Zustand findest du am Dienst.', 'Open the service to see its current state.'],
    ['Dieser Prüfauftrag ist im Beispiel nicht verfügbar.', 'This check is unavailable in the demo.'],
    ['Der Prüfstand hat sich geändert. Öffne den Vorgang erneut.', 'The check has changed. Open the job again.'],
    ['Dieser Prüfschritt ist im aktuellen Zustand nicht verfügbar.', 'This step is unavailable in the current state.'],
    ['Der Entwurf verbindet den externen HTTPS-Proxy über den VPN-Pfad mit dem registrierten Webdienst Medien.', 'The draft connects the external HTTPS proxy to the registered Medien web service over VPN.'],
    ['Entwurf erstellt', 'Draft created'],
    ['Vorgeschlagenes Ziel ist der Webdienst Medien auf nuc-a.', 'The proposed destination is the Medien web service on nuc-a.'],
    ['Interner Abruf geprüft', 'Internal request verified'],
    ['Der simulierte Prüfpunkt meldete den internen Dienst Medien als erreichbar.', 'The simulated probe reported the internal Medien service as reachable.'],
    ['Betreiberfreigabe', 'Operator approval'],
    ['Die Freigabe ist an Ziel, Domain und konkreten Entwurf gebunden.', 'The approval is tied to the destination, domain, and specific draft.'],
    ['Externer Abruf', 'External request'],
    ['Nach der Ausführung prüft ein externer Prüfpunkt die veröffentlichte Adresse.', 'After deployment, an external probe checks the published address.'],
    ['Der Start der Entwicklungs-VM wurde aus dem Ressourcendetail für nuc-a angefordert.', 'The Entwicklung VM start was requested from the nuc-a resource details.'],
    ['VM läuft auf nuc-a', 'VM running on nuc-a'],
    ['Gastzustand von Proxmox bestätigt · 13:52:19', 'Guest state confirmed by Proxmox · 13:52:19'],
    ['Start angefordert', 'Start requested'],
    ['Ziel und Berechtigung für die bestehende VM wurden geprüft.', 'The target and permissions for the existing VM were verified.'],
    ['Proxmox-Auftrag gestartet', 'Proxmox task started'],
    ['Die native Aufgaben-ID wurde dem OpsTend-Auftrag zugeordnet.', 'The native task ID was linked to the OpsTend job.'],
    ['Gastzustand bestätigt', 'Guest state confirmed'],
    ['Proxmox meldete die VM als laufend.', 'Proxmox reported the VM running.'],
    ['Konfigurierte Beziehung', 'Configured relationship'],
    ['Verbindungsprüfung', 'Connectivity check'],
    ['Historische Verbindungsprüfung', 'Historical connectivity check'],
    ['Entwurf', 'Draft'],
    ['Unbekannt', 'Unknown'],
  ]);
  views.englishJobText = (value) => jobEnglish.get(value);
  const jobText = (value) => t(value, views.englishJobText(value) ?? value);
  const exampleJobText = (job, value) => jobs.some(({ id }) => id === job.id) ? jobText(value) : value;

  const routeDecisionId = 'route-decision';
  const visibleInScope = (job, host) => !host || job.host === host || job.relatedHost === host;

  const publicationStages = {
    approved: { tone: 'active', status: ['In der Demo freigegeben', 'Approved in the demo'],
      proof: ['Entscheidung im Browser gespeichert', 'Decision saved in this browser'] },
    applied: { tone: 'active', status: ['Veröffentlichung simuliert', 'Publication simulated'],
      proof: ['Externe HTTPS-Prüfung ausstehend', 'External HTTPS check pending'] },
    verified: { tone: 'success', status: ['Externer HTTPS-Abruf simuliert und bestätigt', 'Simulated external HTTPS request confirmed'],
      proof: ['Der simulierte Prüfpunkt bestätigt den freigegebenen Zugangspfad.', 'The simulated probe confirms the approved access path.'] },
    failed: { tone: 'warn', status: ['Externe HTTPS-Prüfung fehlgeschlagen', 'External HTTPS check failed'],
      proof: ['Der simulierte Prüfpunkt meldet einen Fehler für den freigegebenen Zugangspfad.', 'The simulated probe reports a failure for the approved access path.'] },
    rejected: { tone: 'warn', status: ['Abgelehnt', 'Rejected'], proof: ['Entscheidung im Browser gespeichert', 'Decision saved in this browser'] },
    withdrawn: { tone: 'success', status: ['Veröffentlichung zurückgenommen', 'Publication withdrawn'],
      proof: ['Der Browser hat die Rücknahme simuliert und gespeichert.', 'The browser simulated and saved the withdrawal.'] },
  };
  const stalePublication = {
    tone: 'warn', status: ['Zugangspfad geändert', 'Access path changed'],
    proof: ['Der gespeicherte Stand bezieht sich auf einen früheren Zugangspfad.', 'The saved state refers to an earlier access path.'],
  };
  const publicationEvents = {
    approve: [['Veröffentlichung freigegeben', 'Publication approved'], ['Die Betreiberfreigabe gilt für den geprüften Entwurf.', 'Operator approval applies to the reviewed proposal.']],
    reject: [['Veröffentlichung abgelehnt', 'Publication rejected'], ['Die Betreiberentscheidung wurde im Beispielverlauf gespeichert.', 'The operator decision was saved in the demo history.']],
    apply: [['Veröffentlichung in der Demo angewendet', 'Publication applied in the demo'], ['Das Beispielinventar führt die HTTPS-Weiterleitung als angewendet.', 'The sample inventory records the HTTPS route as applied.']],
    'probe-pass': [['Externer HTTPS-Abruf erfolgreich simuliert', 'Passing external HTTPS request simulated'], ['Der simulierte Prüfpunkt bestätigt den angewendeten Zugangspfad.', 'The simulated probe confirms the applied access path.']],
    'probe-fail': [['Externer HTTPS-Abruf fehlgeschlagen simuliert', 'Failing external HTTPS request simulated'], ['Der simulierte Prüfpunkt meldet einen fehlgeschlagenen HTTPS-Abruf.', 'The simulated probe reports a failed HTTPS request.']],
    withdraw: [['Veröffentlichung zurückgenommen', 'Publication withdrawn'], ['Die simulierte Weiterleitung wurde aus dem Beispielbetrieb zurückgenommen.', 'The simulated route was withdrawn from the demo configuration.']],
    replan: [['Vorschau aktualisiert', 'Preview updated'], ['Ein neuer Entwurf wartet auf Betreiberfreigabe.', 'An updated proposal awaits operator approval.']],
  };
  for (const { status, proof } of [...Object.values(publicationStages), stalePublication]) {
    jobEnglish.set(...status);
    jobEnglish.set(...proof);
  }
  for (const [title, detail] of Object.values(publicationEvents)) {
    jobEnglish.set(...title);
    jobEnglish.set(...detail);
  }
  jobEnglish.set('Simulierter externer Prüfpunkt', 'Simulated external probe');
  jobEnglish.set('Anwendung im Beispielinventar', 'Apply to demo inventory');
  jobEnglish.set('Die Freigabe wurde gespeichert. Die Simulation der Anwendung steht aus.', 'Approval was saved. The application simulation is pending.');

  function publicationJob(job, publication) {
    const { stage, stale, events } = publication;
    const recorded = events.flatMap(({ action, at }) => {
      const copy = publicationEvents[action];
      if (!copy) return [];
      const [title, detail] = copy;
      const actor = action.startsWith('probe-') ? 'Simulierter externer Prüfpunkt' : job.actor;
      return [[at ? formatJobTime(at) : 'Demo', title[0], detail[0], at, undefined, actor]];
    });
    const timeline = [...job.events.slice(0, 2), ...recorded];
    const time = recorded.at(-1)?.[0] ?? job.time;
    if (stage === 'draft') return { ...job, publication, time, events: [...timeline, ...job.events.slice(2)] };
    const phase = stale ? stalePublication : publicationStages[stage];
    if (!phase) return { ...job, publication, time, events: timeline };
    if (!stale && stage === 'approved') timeline.push(['Ausstehend', 'Anwendung im Beispielinventar',
      'Die Freigabe wurde gespeichert. Die Simulation der Anwendung steht aus.']);
    if (!stale && stage === 'applied') timeline.push(job.events[3]);
    return { ...job, publication, time, tone: phase.tone, status: phase.status[0], outcome: phase.status[0],
      verification: phase.proof[0], attention: null, events: timeline };
  }

  const recoveryEvents = {
    'probe-pass': ['Health-Nachprüfung erfolgreich', 'Die simulierte Probe am registrierten Health-Pfad liefert die erwartete Antwort.'],
    'probe-fail': ['Health-Nachprüfung fehlgeschlagen', 'Die simulierte Probe am registrierten Health-Pfad liefert keine Antwort.'],
    retry: ['Erneute Nachprüfung angefordert', 'Der Betreiber stößt die Prüfung ohne weiteren Neustart an.'],
  };

  function recoveryJob(job, recovery) {
    const observations = recovery.events.map(({ action, at, actor }) => {
      if (action === 'retry' && actor === 'zorec') {
        return [formatJobTime(at), 'Zorec hat eine Health-Nachprüfung angefordert',
          'Zorec nutzt die freigegebene einmalige Health-Nachprüfung am registrierten Pfad.', at, undefined, 'Zorec'];
      }
      return [formatJobTime(at), ...recoveryEvents[action], at, undefined, action === 'retry' ? 'Betreiber' : job.actor];
    });
    const recorded = [...job.events.slice(0, 3), ...observations];
    const time = observations.at(-1)?.[0] ?? job.time;
    if (recovery.phase === 'healthy') return {
      ...job, time, status: 'Wiederhergestellt', tone: 'success', attention: null,
      outcome: 'Sensorik antwortet wieder',
      verification: 'Simulierte Health-Nachprüfung erfolgreich',
      events: recorded,
    };
    if (recovery.phase === 'failed') return {
      ...job, time, status: 'Entscheidung ausstehend', tone: 'warn',
      outcome: 'Sensorik antwortet weiterhin nicht',
      verification: 'Simulierte Health-Nachprüfung fehlgeschlagen',
      attention: {
        ...job.attention,
        title: 'Sensorik antwortet weiterhin nicht',
        impact: recovery.events.some(({ action }) => action === 'retry') ? 'Die erneute Health-Nachprüfung ist fehlgeschlagen.'
          : 'Die Health-Nachprüfung nach dem Neustart ist fehlgeschlagen.',
        status: 'Wiederanlauf nicht bestätigt',
        action: 'Störung ansehen',
      },
      nextDecision: {
        kind: 'decision',
        title: 'Sensorik erneut prüfen',
        impact: 'Der erlaubte Neustart wurde ausgeführt. Du kannst eine weitere Health-Prüfung anstoßen.',
        status: 'Deine Entscheidung ist gefragt',
        action: 'Nachprüfung entscheiden',
      },
      recovery,
      events: recorded,
    };
    if (recovery.phase === 'pending') {
      if (!observations.length) return { ...job, recovery };
      const latest = recovery.events.at(-1);
      const autonomous = latest.action === 'retry' && latest.actor === 'zorec';
      return {
        ...job, time, recovery,
        verification: autonomous ? 'Von Zorec angestoßene Health-Nachprüfung läuft' : 'Erneute Health-Nachprüfung läuft',
        attention: {
          ...job.attention,
          impact: autonomous ? 'Zorec hat eine weitere Health-Prüfung angestoßen.' : 'Du hast eine weitere Health-Prüfung angestoßen.',
          status: 'Zorec prüft das neue Ergebnis',
        },
        events: [...recorded, ['Läuft', 'Erneute Health-Nachprüfung', 'Die simulierte Probe wartet auf ein Ergebnis.']],
      };
    }
    return {
      ...job, time, status: 'Früherer Vorgang', attention: null,
      verification: 'Den aktuellen Zustand findest du am Dienst.',
      events: recorded,
    };
  }

  function exampleJobs(state) {
    const publication = window.opstendPublications?.get(state, 'medien-publication');
    const sensorik = state.inventory.services.find((service) => service.id === 'sensorik');
    return jobs.map((job) => {
      if (job.id === 'route' && publication) return publicationJob(job, publication);
      if (job.id === 'sensorik') {
        const recovery = window.opstendDemo.recoveryFor(sensorik);
        if (recovery) return recoveryJob(job, recovery);
      }
      return job;
    });
  }

  views.attention = (state) => [...exampleJobs(state), ...hostMaintenanceJobs(state), ...networkRuleJobs(state),
    ...window.opstendSelfUpdateView.jobs(state), ...runtimeIncidents(state)].flatMap((job) => {
    if (!job.attention || !visibleInScope(job, state.host)) return [];
    return job.nextDecision ? [job, { ...job, attention: job.nextDecision }] : [job];
  });

  const settingsGroups = [
    ['OpsTend', [
      ['access', 'Zugriff und Rollen', 'anmeldung oidc mfa ssh ldap token sitzung netz login session roles', 'Access and roles'],
      ['system', 'Darstellung', 'farbschema hell dunkel system theme light dark', 'Appearance'],
      ['language', 'Sprache', 'oberfläche konto login profil deutsch englisch zorec locale language german english preferences', 'Language'],
      ['ai', 'Zorec und KI', 'modell anbieter werkzeug berechtigung shell admin lesen edit bericht internet recherche automation vollautonom model provider tools permissions autonomy chatverlauf aufbewahrung chat history retention', 'Zorec and AI'],
      ['api', 'System-API', 'api schnittstelle chat auftrag verbindung automation', 'System API'],
      ['updates', 'OpsTend-Updates', 'eigenupdate release patches auto benachrichtigung wartungsfenster rollback notifications', 'OpsTend updates'],
    ]],
    ['Plattform', [
      ['hosts', 'Hostverwaltung', 'host agent registrierung aufnahme bestand inventar austritt reset ressourcen budget enrollment inventory', 'Host management'],
      ['integrations', 'Integrationen', 'proxmox podman unifi dns ipa zeit identität identity', 'Integrations'],
      ['placement', 'Zentrale Dienste', 'platzierung repliken controller quorum vpn placement replicas', 'Core services'],
      ['features', 'Funktionskatalog', 'deployment pve vm container acl netz schalter network', 'Feature catalog'],
    ], 'Platform'],
    ['Betrieb', [
      ['policies', 'Richtlinien', 'wartungsfenster selbstheilung freigabe migration maintenance approval', 'Policies'],
      ['backup', 'Schutz', 'backup nas pbs restic sicherung wiederherstellung recovery restore', 'Protection'],
    ], 'Operations'],
  ];

  function adapterTransitionDetail(state, transition) {
    const { escape } = state;
    const { from, to, rows } = transition;
    return `<div class="manage-adapter-change"><h3>Adapter-Wechsel</h3>
      <dl class="manage-job-meta">
        <div><dt>Bisher</dt><dd>Adapter ${escape(from.version)} · Konfigurationsrevision ${escape(from.revision)}</dd></div>
        <div><dt>Danach</dt><dd>Adapter ${escape(to.version)} · Konfigurationsrevision ${escape(to.revision)}</dd></div>
      </dl>
      ${window.opstendObjectUi.adapterChangeTable(state, [], rows, "Danach")}
    </div>`;
  }

  function networkPortDetail(state, change) {
    const { escape } = state;
    const networks = new Map(state.inventory.networks.map((network) => [network.id, network.name]));
    const vlanName = (id) => networks.get(id) ?? id ?? '–';
    const taggedNames = (config) => config.taggedVlans.map(vlanName).join(', ') || '–';
    const modeName = (config) => ({ access: 'Access', trunk: 'Trunk' }[config.mode] ?? config.mode);
    const rows = [
      ['Portmodus', modeName],
      ['Natives VLAN', (config) => vlanName(config.nativeVlan)],
      ['Getaggte VLANs', taggedNames],
    ].map(([label, display]) => ({ label, before: display(change.before), after: display(change.after) }));
    return `<div class="manage-adapter-change"><h3>VLAN-Zuordnung</h3>
      <p class="compact">Portrevision ${escape(change.revision)}</p>
      ${window.opstendObjectUi.adapterChangeTable(state, [], rows, 'Danach')}
    </div>`;
  }

  const pendingRecovery = new Map();

  function recoveryControls(state, job) {
    if (!job.recovery) return '';
    const { escape } = state;
    const { phase, revision } = job.recovery;
    const busy = pendingRecovery.get(job.serviceId) === revision;
    const button = (action, label, primary = false) => `<button type="button" class="button${primary ? ' primary' : ''}"
      data-recovery-action="${action}" ${busy ? 'disabled' : ''}>${label}</button>`;
    return `<section class="manage-decision" aria-labelledby="recovery-heading" aria-busy="${busy}"
      data-recovery-panel="${escape(job.serviceId)}" data-recovery-revision="${escape(revision)}">
      <h3 id="recovery-heading">${phase === 'failed' ? t('Über die Nachprüfung entscheiden', 'Decide on another health check')
        : t('Health-Ergebnis in der Demo', 'Demo health check result')}</h3>
      <p>${phase === 'failed'
        ? t('Der erlaubte Neustart wurde bereits ausgeführt. Eine erneute Health-Prüfung erfasst den Zustand des Dienstes.',
          'The approved restart has already run. Another health check will report the service state.')
        : t('Wähle das Ergebnis der simulierten Probe am registrierten Health-Pfad.', 'Choose the simulated result for the registered health check path.')}</p>
      <div class="service-tools">${phase === 'failed'
        ? button('retry', t('Erneute Prüfung anstoßen', 'Start another check'), true)
        : button('probe-pass', t('Prüfung erfolgreich simulieren', 'Simulate a passing check'), true)
          + button('probe-fail', t('Prüfung fehlgeschlagen simulieren', 'Simulate a failing check'))}
        <button type="button" class="text-button" data-view="settings" data-settings-tab="policies" data-host="${escape(job.host)}">${t('Richtlinie ansehen', 'View policy')}</button>
      </div>
      <p id="recovery-notice" role="status" tabindex="-1"></p>
    </section>`;
  }

  function provisionDetail(state, job) {
    const { cpu, ram, network, provisioning } = job.guest;
    const { escape } = state;
    return `<section class="manage-decision" aria-labelledby="guest-provision-heading">
      <h3 id="guest-provision-heading">Anlage aus Vorlage</h3>
      <dl class="manage-job-meta">
        <div><dt>Vorlage</dt><dd>${escape(provisioning.templateTitle)}</dd></div>
        <div><dt>Netz</dt><dd>${escape(network)}</dd></div>
        <div><dt>CPU</dt><dd>${escape(cpu)}</dd></div>
        <div><dt>RAM</dt><dd>${escape(ram)}</dd></div>
        <div><dt>Speicher</dt><dd>${escape(provisioning.store)} · ${escape(provisioning.disk)} GiB</dd></div>
        <div><dt>Nach Anlage</dt><dd>${provisioning.start ? 'Starten' : 'Gestoppt bereitstellen'}</dd></div>
      </dl>
      ${job.provisionPending ? `<div class="service-tools">
        <button type="button" class="button primary" data-guest-provision-confirm="${escape(job.serviceId)}">Anlage in der Demo bestätigen</button>
      </div><p id="guest-provision-notice" role="status">Simuliere die Rückmeldung des Zielhosts im Browser.</p>` : ''}
    </section>`;
  }

  function jobResources(state, job, service) {
    const { inventory, escape } = state;
    const hosts = [job.host, job.relatedHost, service?.host].filter(Boolean);
    const machines = [...new Set(hosts)].flatMap((id) => inventory.hosts.filter((host) => host.id === id));
    const network = service && inventory.networks.find((entry) => views.serviceInNetwork(entry, service));
    const link = inventory.links.find(({ id }) => id === job.linkId);
    const button = (label, route, style = 'text-button') => `<button type="button" class="${style}" ${Object.entries(route)
      .map(([key, value]) => `data-${key}="${escape(value)}"`).join(' ')}>${escape(label)}</button>`;
    const field = (label, control, context = '') => `<div><dt>${label}</dt><dd>${control}${context ? `<small>${escape(context)}</small>` : ''}</dd></div>`;
    const fields = machines.map(({ id, name }) => field(id === job.host ? t('Ausführungshost', 'Execution host')
      : id === job.relatedHost ? t('Zielhost', 'Target host') : t('Aktueller Diensthost', 'Current service host'),
    button(name, { view: 'host', host: id })));
    if (service) fields.unshift(field(t('Dienst', 'Service'), button(service.name, { view: 'service', host: service.host, 'service-id': service.id })));
    if (network) fields.push(field(t('Dienstnetz', 'Service network'), button(network.name, { view: 'network-detail', host: service.host, 'network-id': network.id })));
    if (link) {
      const endpoints = [link.from, link.to].map((id) => [...inventory.hosts, ...inventory.services, ...inventory.devices].find((item) => item.id === id));
      if (endpoints.every(Boolean)) {
        const linkHost = endpoints.map((item) => item.host || inventory.hosts.find(({ id }) => id === item.id)?.id).filter(Boolean);
        const scope = linkHost.includes(state.host) ? state.host : linkHost[0] || '';
        const evidence = window.opstendDemo.linkEvidence(link);
        fields.push(field(t('Verbindung', 'Connection'), button(link.label, { view: 'topology', host: scope, layer: link.layer, 'topology-focus': link.id }),
          `${endpoints.map((item) => item.name).join(' ↔ ')} · ${jobText(evidence.type)}`));
      }
    }
    if (!fields.length) return '';
    return `<section class="manage-resources" aria-labelledby="manage-resource-title">
      <h3 id="manage-resource-title">${t('Betroffene Ressourcen', 'Affected resources')}</h3>
      <dl class="manage-job-meta">${fields.join('')}</dl>
      ${service ? `<div class="service-tools">
        ${button(t(`${service.name} in Topologie`, `${service.name} in topology`),
          { view: 'topology', host: service.host, layer: 'all', 'topology-focus': service.id }, 'button')}
        ${button(t(`${service.name} im Protokoll`, `${service.name} in event log`),
          { view: 'events', host: service.host, 'event-subject': `service:${service.id}` }, 'button')}
      </div>` : ''}
    </section>`;
  }

  const ruleDecisionFeedback = new Map();
  const decidingRules = new Set();
  const ruleEffect = (effect) => effect === 'allow' ? t('Erlauben', 'Allow') : t('Blockieren', 'Block');

  function networkRuleDetail(state, job) {
    const { escape } = state;
    const change = job.ruleChange;
    const rule = window.opstendNetworkRules.get(state, change.ruleId);
    const pending = change.status === 'pending';
    const canApprove = rule?.editable && rule.pending?.id === change.id
      && rule.host === change.host && rule.revision === change.revision && rule.effect === change.before;
    const deciding = decidingRules.has(change.id);
    const approve = (decision, label, primary = false) => `<button type="button" class="button${primary ? ' primary' : ''}"
      data-network-rule-decision="${decision}" ${deciding ? 'disabled' : ''}>${label}</button>`;
    const date = (at) => `<time datetime="${escape(at)}">${escape(formatJobTime(at))}</time>`;
    return `<section class="manage-decision" aria-labelledby="network-rule-review-title" data-network-rule-review="${escape(change.id)}"
      data-network-rule-review-host="${escape(state.host)}" aria-busy="${deciding}">
      <h3 id="network-rule-review-title">${t('Regelwirkung', 'Rule action')}</h3>
      <dl class="manage-job-meta">
        <div><dt>${t('Ausgangsrevision', 'Base revision')}</dt><dd>${escape(change.revision)}</dd></div>
        <div><dt>${t('Vorgemerkt am', 'Submitted')}</dt><dd>${date(change.requestedAt)}</dd></div>
        <div><dt>${t('Bisherige Wirkung', 'Previous action')}</dt><dd>${ruleEffect(change.before)}</dd></div>
        <div><dt>${change.status === 'applied' ? t('Übernommene Wirkung', 'Applied action') : t('Vorgeschlagene Wirkung', 'Proposed action')}</dt>
          <dd>${ruleEffect(change.after)}</dd></div>
        ${change.decidedAt ? `<div><dt>${t('Entschieden am', 'Decided')}</dt><dd>${date(change.decidedAt)}</dd></div>` : ''}
      </dl>
      <p>${t('Die Entscheidung gilt für das Beispielinventar im Browser. Verbindungsproben stehen separat in der Topologie.',
        'The decision applies to the browser inventory. The topology shows connectivity checks separately.')}</p>
      ${pending && !canApprove ? `<p>${t('Regel oder Ausgangsrevision hat sich geändert. Du kannst den Entwurf ablehnen.',
        'The rule or base revision changed. You can reject the draft.')}</p>` : ''}
      <div class="service-tools">
        ${pending && canApprove ? approve('approve', t('In der Demo übernehmen', 'Apply in the demo'), true) : ''}
        ${pending ? approve('reject', t('Ablehnen', 'Reject')) : ''}
        ${rule ? `<button type="button" class="text-button" data-view="network-rule" data-rule-id="${escape(change.ruleId)}">
          ${t('Netzregel öffnen', 'Open network rule')}</button>` : ''}
        <button type="button" class="text-button" data-view="events" data-event-subject="rule:${escape(change.ruleId)}">
          ${t('Regel im Protokoll', 'Rule in event log')}</button>
      </div>
      <p data-network-rule-notice role="status" tabindex="-1">${escape(ruleDecisionFeedback.get(change.id) || '')}</p>
    </section>`;
  }

  const maintenanceFeedback = new Map();
  const advancingMaintenance = new Map();
  const maintenanceActions = {
    pending: [['approve', ['Wartung freigeben', 'Approve maintenance']], ['reject', ['Ablehnen', 'Reject']]],
    approved: [['start', ['Neustart im Fenster simulieren', 'Simulate restart in the window']], ['reject', ['Wartung absagen', 'Cancel maintenance']]],
    active: [['finish', ['Wiederanlauf simulieren', 'Simulate recovery']]],
  };
  const maintenanceHandling = {
    restart: ['Unterbrechung und Wiederanlauf', 'Interruption and restart'],
    'leave-stopped': ['Bleibt gestoppt', 'Remains stopped'],
    blocked: ['Blockiert', 'Blocked'],
  };
  const maintenanceDate = new Intl.DateTimeFormat('de-DE', { dateStyle: 'medium', timeZone: 'Europe/Berlin' });
  const maintenanceDateEn = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeZone: 'Europe/Berlin' });
  const maintenanceActor = (actor) => actor === 'zorec' ? 'Zorec' : t('Betreiber · Demo', 'Operator · demo');

  function maintenanceDetail(state, record) {
    const { escape, inventory } = state;
    const { id, host, revision, stage, window: slot, workloads } = record;
    const busy = advancingMaintenance.get(id) === revision;
    const managed = inventory.hosts.some((item) => item.id === host);
    const approval = record.events.find(({ action }) => action === 'approve');
    const buttons = maintenanceActions[stage]?.map(([action, label], index) => `<button type="button" class="button${index ? '' : ' primary'}"
      data-host-maintenance-action="${action}" ${busy ? 'disabled' : ''}>${t(...label)}</button>`).join('') ?? '';
    return `<section class="manage-decision" aria-labelledby="host-maintenance-review-title" data-host-maintenance-review="${escape(id)}"
      data-host-maintenance-revision="${escape(revision)}" data-host-maintenance-scope="${escape(state.host)}" aria-busy="${busy}">
      <h3 id="host-maintenance-review-title">${t('Wartungsplan', 'Maintenance plan')}</h3>
      <dl class="manage-job-meta">
        <div><dt>${t('Wirksames Wartungsfenster', 'Effective maintenance window')}</dt><dd>${escape(t(slot.label, slot.labelEn))} · ${escape(slot.timezone || 'Europe/Berlin')}</dd></div>
        <div><dt>${t('Geplanter Termin', 'Scheduled date')}</dt><dd><time datetime="${escape(slot.startAt)}">${escape(t(maintenanceDate, maintenanceDateEn).format(new Date(slot.startAt)))}</time></dd></div>
        <div><dt>${t('Herkunft', 'Source')}</dt><dd>${escape(t(slot.source, slot.sourceEn))}</dd></div>
        <div><dt>${t('Auftragsrevision', 'Job revision')}</dt><dd>${escape(revision)}</dd></div>
        ${approval ? `<div><dt>${t('Freigegeben durch', 'Approved by')}</dt><dd>${maintenanceActor(approval.actor)}</dd></div>` : ''}
      </dl>
      <h3>${t('Auswirkung auf Gäste und Dienste', 'Impact on guests and services')}</h3>
      ${workloads.length ? `<ul class="feed" role="list">${workloads.map(({ id: workloadId, name, kind, handling, reason, reasonEn }) => {
        const present = inventory.services.some((item) => item.id === workloadId && item.host === host);
        return `<li><div>${present ? `<button type="button" class="text-button" data-view="service" data-host="${escape(host)}"
          data-service-id="${escape(workloadId)}">${escape(name)}</button>` : `<strong>${escape(name)}</strong>`}
          <p>${escape(kind === 'Container · Podman' ? t(kind, 'Podman container') : kind)} · ${t(...maintenanceHandling[handling])}</p><p>${escape(t(reason, reasonEn))}</p></div></li>`;
      }).join('')}</ul>` : `<p>${t('Auf dem Host sind keine Gäste oder Dienste erfasst.', 'No guests or services are recorded on this host.')}</p>`}
      <p>${t('Die Zeitschritte und der Neustart werden im Browser simuliert.', 'The time steps and restart are simulated in the browser.')}</p>
      <div class="service-tools">
        ${buttons}
        ${managed ? `<button type="button" class="text-button" data-view="host-maintenance" data-host="${escape(host)}">${t('Wartungsplanung öffnen', 'Open maintenance planning')}</button>` : ''}
        <button type="button" class="text-button" data-view="events" data-host="${escape(managed ? host : '')}" data-event-kind="maintenance">${t('Wartung im Protokoll', 'Maintenance in event log')}</button>
      </div>
      <p data-host-maintenance-notice role="status" tabindex="-1">${escape(maintenanceFeedback.get(id) || '')}</p>
    </section>`;
  }

  const publicationFeedback = new Map();
  const advancingPublications = new Map();
  const publicationActions = {
    draft: ['approve', 'reject'], approved: ['apply', 'withdraw'], applied: ['probe-pass', 'probe-fail', 'withdraw'],
    failed: ['probe-pass', 'probe-fail', 'withdraw'], verified: ['withdraw'], rejected: ['replan'], withdrawn: ['replan'],
  };
  const publicationActionLabels = {
    approve: ['In der Demo freigeben', 'Approve in the demo'], reject: ['Ablehnen', 'Reject'],
    apply: ['Veröffentlichung simulieren', 'Simulate publication'],
    'probe-pass': ['Externen HTTPS-Abruf erfolgreich simulieren', 'Simulate a passing external HTTPS request'],
    'probe-fail': ['Externen HTTPS-Abruf fehlgeschlagen simulieren', 'Simulate a failing external HTTPS request'],
    withdraw: ['Veröffentlichung zurücknehmen', 'Withdraw publication'], replan: ['Neue Vorschau erstellen', 'Create a new preview'],
  };
  const boundPublicationActions = new Set(['approve', 'apply', 'probe-pass', 'probe-fail']);
  const primaryPublicationActions = new Set(['approve', 'apply', 'probe-pass', 'replan']);

  function publicationDetail(state, publication) {
    const { escape } = state;
    const { id, domain, stage, revision, binding, proxyHost, serviceId, targetHost, ready, stale, error, errorEn } = publication;
    const pending = advancingPublications.get(id) === revision;
    const draft = stage === 'draft';
    const service = state.inventory.services.find(({ id }) => id === serviceId);
    const actions = stale && stage === 'approved' ? ['replan', 'withdraw'] : publicationActions[stage] ?? [];
    const controls = actions.map((action) => {
      const blocked = action === 'replan' ? !ready : boundPublicationActions.has(action) && (!ready || stale);
      return `<button type="button" class="button${primaryPublicationActions.has(action) ? ' primary' : ''}"
        data-publication-action="${action}" ${pending || blocked ? 'disabled' : ''}>${t(...publicationActionLabels[action])}</button>`;
    }).join('');
    return `<section class="manage-decision" aria-labelledby="decision-heading" data-publication-review="${escape(id)}" aria-busy="${pending}"
      data-publication-revision="${escape(revision)}" data-publication-scope="${escape(state.host)}" data-publication-binding="${escape(binding)}">
      <h3 id="decision-heading">${draft ? t('Deine Entscheidung', 'Your decision') : t('HTTPS-Veröffentlichung', 'HTTPS publication')}</h3>
      <dl class="manage-job-meta">
        <div><dt>${t('Externe Adresse', 'External address')}</dt><dd>https://${escape(domain)}</dd></div>
        <div><dt>${t('Ziel', 'Target')}</dt><dd>${escape(service?.name ?? serviceId)} · ${escape(targetHost)}</dd></div>
        <div><dt>${t('HTTPS-Proxy', 'HTTPS proxy')}</dt><dd>${escape(proxyHost)} · ${t('über WireGuard', 'over WireGuard')}</dd></div>
      </dl>
      <p>${t('Die Demo simuliert Anwendung und externen HTTPS-Abruf im Beispielinventar.', 'The demo simulates application and the external HTTPS request in the sample inventory.')}</p>
      ${error ? `<p>${escape(t(error, errorEn ?? error))}</p>` : ''}
      <div class="service-tools">${controls}
        <button type="button" class="text-button" data-view="access-detail" data-publication-id="${escape(id)}">
          ${t('Zugangspfad öffnen', 'Open access path')}</button>
      </div>
      <p data-publication-notice role="status" tabindex="-1">${escape(publicationFeedback.get(id) || '')}</p>
    </section>`;
  }

  function changeDetail(state, job) {
    if (!job) {
      return `<section class="panel manage-empty"><h2>${t('Keine Aufträge in dieser Auswahl', 'No jobs in this scope')}</h2>
        <p>${t('Wähle einen anderen Host oder die Flotte, um weitere Aufträge zu sehen.', 'Select another host or the fleet to see more jobs.')}</p></section>`;
    }

    const { escape } = state;
    const service = state.inventory.services.find((item) => item.id === job.serviceId);
    const adapter = job.adapter && window.opstendDemo.adapterSettings(service);
    const fields = adapter?.version === job.adapter?.version && adapter ? adapter.fields : [];
    const eventItems = job.events.map(([time, label, body, , subject], index) => {
      const pending = time === 'Ausstehend' || time === 'Läuft';
      const id = jobEventId(job, index, subject);
      const selected = state.jobEvent === id;
      return `<li class="manage-event${pending ? ' manage-event-pending' : ''}${selected ? ' manage-event-selected' : ''}"
        data-job-event-row="${escape(id)}" tabindex="-1" ${selected ? 'aria-current="true"' : ''}>
        ${pending ? `<span>${escape(jobText(time))}</span>` : `<time>${escape(time)}</time>`}
        <div><strong>${escape(exampleJobText(job, label))}</strong><p>${escape(exampleJobText(job, body))}</p></div>
      </li>`;
    }).join('');

    return `<section class="panel manage-job-detail" data-manage-job-detail="${escape(job.id)}" aria-label="${t('Auftragsdetails', 'Job details')}">
      <div class="manage-panel-heading"><div><p class="eyebrow">${escape(jobText(job.type))}</p><h2 id="manage-job-title" tabindex="-1">${escape(exampleJobText(job, job.title))}</h2></div>
        <button type="button" class="text-button manage-job-list-link" data-open-job-list>${t('Zur Auftragsliste', 'Back to jobs')}</button></div>
      <div class="manage-outcome manage-outcome-${job.tone}" tabindex="-1">
        <span class="manage-outcome-icon" aria-hidden="true">${job.tone === 'success' ? '✓' : '◷'}</span>
        <div><strong>${escape(jobText(job.outcome))}</strong><p>${escape(jobText(job.verification))}</p></div>
      </div>
      <p class="manage-description">${escape(jobText(job.context))}</p>
      <dl class="manage-job-meta">
        <div><dt>${t('Ziel', 'Target')}</dt><dd>${escape(job.target)}</dd></div><div><dt>${t('Auslöser', 'Initiator')}</dt><dd>${escape(jobText(job.actor))}</dd></div>
        ${job.runtime && !job.runtimeExecution ? `<div><dt>${t('Laufzeit vorher', 'Runtime before')}</dt><dd>${escape(job.runtime.before)}</dd></div>
          <div><dt>${t('Laufzeit nachher', 'Runtime after')}</dt><dd>${escape(job.runtime.after)}</dd></div>` : ''}
      </dl>
      ${job.publication ? publicationDetail(state, job.publication) : ''}
      ${recoveryControls(state, job)}
      ${window.opstendAutonomyUI?.renderJob?.(state, job) ?? ''}
      ${job.ruleChange ? networkRuleDetail(state, job) : ''}
      ${job.maintenance ? maintenanceDetail(state, job.maintenance) : ''}
      ${job.runtimeExecution ? runtimeDetail(state, job) : ''}
      ${jobResources(state, job, service)}
      ${job.guest ? provisionDetail(state, job) : ''}
      ${job.adapter ? `<div class="manage-adapter-change"><h3>Einstellungsänderungen</h3>
        <p class="compact">Adapter ${escape(job.adapter.version)} · Konfigurationsrevision ${escape(job.adapter.revision)}</p>
        ${window.opstendObjectUi.adapterChangeTable(state, fields, job.adapter.changes)}</div>` : ''}
      ${job.adapterTransition ? adapterTransitionDetail(state, job.adapterTransition) : ''}
      ${job.portChange ? networkPortDetail(state, job.portChange) : ''}
      <h3>${t('Ablauf', 'Timeline')}</h3>
      <ol class="manage-timeline">${eventItems}</ol>
      ${service ? `<button class="button" data-view="service" data-host="${escape(service.host)}" data-service-id="${escape(service.id)}">
        ${job.guest || job.runtimeExecution?.provider === 'pve'
          ? t(`Gast ${escape(service.name)} öffnen`, `Open guest ${escape(service.name)}`)
          : t(`Dienst ${escape(service.name)} öffnen`, `Open service ${escape(service.name)}`)}</button>` : ''}
      ${job.portId ? `<button type="button" class="button" data-view="network-port" data-port-id="${escape(job.portId)}">${t('Port öffnen', 'Open port')}</button>` : ''}
      ${job.selfUpdate ? `<button type="button" class="button" data-view="settings" data-settings-tab="updates" data-host="${escape(job.host)}">${t('OpsTend-Updates öffnen', 'Open OpsTend updates')}</button>` : ''}
      ${job.hostEnrollment ? `<button type="button" class="button" data-view="settings" data-settings-tab="hosts">${t('Hostverwaltung öffnen', 'Open host management')}</button>` : ''}
    </section>`;
  }

  const runtimeLabels = { running: 'Läuft', stopped: 'Gestoppt' };
  jobEnglish.set('Laufzeit', 'Runtime');
  const operationLabels = window.opstendDemo.runtimeLabels;
  const runtimeStages = {
    queued: ['active', 'Ausführung ausstehend', 'Execution pending', 'Die bestätigte Gastaktion wartet auf ihre Ausführung.', 'The confirmed guest action is ready to run.'],
    reconcile: ['warn', 'Auftragsstatus unklar', 'Execution status uncertain', 'Nach dem simulierten Antwortverlust ist der Ausführungsstatus abzugleichen.', 'The execution status needs to be reconciled after the simulated lost response.'],
    dispatched: ['active', 'Ausführung läuft', 'Execution in progress', 'Der simulierte Ausführungsauftrag ist bekannt. Sein Ergebnis steht aus.', 'The simulated execution request is known. Its result is pending.'],
    readback: ['active', 'Rückmeldung ausstehend', 'Readback pending', 'Die Ausführung meldet Erfolg. Der beobachtete Zustand am Ziel steht aus.', 'Execution reported success. The observed state at the target is pending.'],
    finished: ['success', 'Zielzustand bestätigt', 'Target state confirmed', 'Das Beispielinventar hat den beobachteten Laufzustand übernommen.', 'The demo inventory recorded the observed runtime state.'],
    failed: ['warn', 'Ausführung fehlgeschlagen', 'Execution failed', 'Die simulierte Ausführung meldet einen Fehler. Prüfe den beobachteten Zustand am Ziel.', 'Simulated execution reported a failure. Check the observed state at the target.'],
    canceled: ['warn', 'Auftrag abgebrochen', 'Job canceled', 'Der Abbruch wurde vor der Ausführung bestätigt.', 'The cancellation was confirmed before execution.'],
  };
  const runtimeActions = {
    queued: ['dispatch', 'lose-response', 'cancel'], reconcile: ['reconcile-task'],
    dispatched: ['task-pass', 'task-fail'], readback: ['confirm-state'],
  };
  const runtimeActionLabels = {
    dispatch: ['Ausführung simulieren', 'Simulate execution'],
    'lose-response': ['Antwortverlust simulieren', 'Simulate a lost response'],
    'reconcile-task': ['Auftrag abgleichen', 'Reconcile execution'],
    'task-pass': ['Ausführungserfolg simulieren', 'Simulate successful execution'],
    'task-fail': ['Fehler simulieren', 'Simulate failure'],
    'confirm-state': ['Gastzustand bestätigen', 'Confirm guest state'],
    cancel: ['Auftrag abbrechen', 'Cancel job'],
  };
  const runtimeEventLabels = {
    request: [['Vorschau bestätigt', 'Preview confirmed'], ['Der Browser hat die Gastaktion zur Ausführung vorgemerkt.', 'The browser queued the guest action for execution.']],
    dispatch: [['Ausführung angenommen', 'Execution accepted'], ['Die Simulation hat eine Ausführungsreferenz zugeordnet.', 'The simulation assigned an execution reference.']],
    'lose-response': [['Antwort bei der Ausführung verloren', 'Execution response lost'], ['Die Referenz muss über den Statusabgleich ermittelt werden.', 'The reference must be found through reconciliation.']],
    'reconcile-task': [['Ausführungsauftrag wiedergefunden', 'Execution request found'], ['Der Abgleich hat den bereits gestarteten Vorgang zugeordnet.', 'Reconciliation found the execution already started.']],
    'task-pass': [['Ausführung erfolgreich', 'Execution succeeded'], ['Als Nächstes folgt der Abgleich des beobachteten Laufzustands am Ziel.', 'The next step is to verify the observed runtime state at the target.']],
    'task-fail': [['Ausführung fehlgeschlagen', 'Execution failed'], ['Die simulierte Ausführung meldet einen Fehler.', 'Simulated execution reported a failure.']],
    'confirm-state': [['Laufzeitstatus übernommen', 'Runtime state recorded'], ['Der Browser hat das beobachtete Ergebnis im Beispielinventar gespeichert.', 'The browser saved the observed result to the demo inventory.']],
    cancel: [['Auftrag abgebrochen', 'Job canceled'], ['Der vorgemerkte Ausführungsschritt wurde abgebrochen.', 'The queued execution was canceled.']],
  };
  const advancingRuntime = new Map();
  const runtimeFeedback = new Map();
  const jobTime = new Intl.DateTimeFormat('de-DE', { dateStyle: 'short', timeStyle: 'medium' });
  const jobEnglishTime = new Intl.DateTimeFormat('en-GB', { dateStyle: 'short', timeStyle: 'medium' });

  function formatJobTime(timestamp) {
    const date = new Date(timestamp);
    return Number.isNaN(date.getTime()) ? 'Demo' : t(jobTime, jobEnglishTime).format(date);
  }

  function runtimeJob(item) {
    const at = formatJobTime(item.at);
    const operation = operationLabels[item.operation] || 'Laufzeit ändern';
    const stage = Object.hasOwn(runtimeStages, item.stage) ? runtimeStages[item.stage] : null;
    if (stage && Array.isArray(item.events)) {
      const [tone, statusDe, statusEn, detailDe, detailEn] = stage;
      const status = t(statusDe, statusEn);
      const verification = t(detailDe, detailEn);
      const action = t(operation, { start: 'Start', stop: 'Shut down', restart: 'Restart' }[item.operation] || 'Change runtime');
      const states = { running: t('Läuft', 'Running'), stopped: t('Gestoppt', 'Stopped') };
      const stateLabel = (value) => states[value] || t('Unbekannt', 'Unknown');
      const events = item.events.flatMap((event) => {
        if (!Object.hasOwn(runtimeEventLabels, event?.action)) return [];
        const [title, detail] = runtimeEventLabels[event.action];
        return [[formatJobTime(event.at), t(...title), t(...detail), event.at]];
      });
      const title = `${item.name} · ${action}`;
      return {
        id: item.id, serviceId: item.serviceId, host: item.host, at: item.at, time: at,
        title, type: 'Laufzeit', status, tone,
        target: t(`${item.name} auf ${item.host}`, `${item.name} on ${item.host}`), actor: t('Betreiber · Demo', 'Operator · Demo'),
        context: t('Gastaktionen und Laufzeitbeobachtungen werden im Browser simuliert.', 'Guest actions and runtime observations are simulated in the browser.'),
        outcome: status, verification, runtimeExecution: item,
        runtime: { before: stateLabel(item.before), after: stateLabel(item.after), observed: stateLabel(item.stage === 'finished' ? item.after : item.before) },
        attention: ['reconcile', 'failed'].includes(item.stage) ? {
          kind: 'incident', title, status, impact: verification,
          action: t('Laufzeitauftrag öffnen', 'Open runtime job'),
        } : null,
        events,
      };
    }
    return {
      id: item.id, serviceId: item.serviceId, host: item.host, time: at, at: item.at,
      title: `${item.name} · ${operation}`, type: 'Laufzeit', status: item.status, tone: 'success',
      target: `${item.name} auf ${item.host}`, actor: 'Betreiber · Demo',
      context: 'Der simulierte Auftragsablauf wurde im lokalen Beispielinventar gespeichert.',
      outcome: 'In der Demo ausgeführt',
      verification: item.after === 'stopped'
        ? 'Ergebnis aus dem Beispielinventar. Die Health-Prüfung pausiert bei gestoppter Laufzeit.'
        : 'Ergebnis aus dem Beispielinventar. Eine Health-Prüfung ist offen.',
      runtime: {
        before: runtimeLabels[item.before] || 'Unbekannt',
        after: runtimeLabels[item.after] || 'Unbekannt',
      },
      events: [
        [at, 'Vorschau bestätigt', operation],
        [at, 'Laufzeitstatus übernommen', 'Der Demo-Auftrag meldet den neuen Zustand am Dienst.'],
      ],
    };
  }

  function runtimeIncidents(state) {
    const seen = new Set();
    const incidents = [];
    for (const item of state.inventory.changes) {
      if (item.kind !== 'runtime' || seen.has(item.serviceId)) continue;
      seen.add(item.serviceId);
      if (item.stage === 'reconcile' || item.stage === 'failed') incidents.push(runtimeJob(item));
    }
    return incidents;
  }

  function runtimeDetail(state, job) {
    const { escape } = state;
    const { id, stage, revision, provider, taskId, attemptedAt } = job.runtimeExecution;
    const { before, after, observed } = job.runtime;
    const busy = advancingRuntime.get(id) === revision;
    const source = provider === 'pve' ? t('Proxmox-Task · Demo', 'Proxmox task · Demo') : t('Podman-Executor · Demo', 'Podman executor · Demo');
    const reference = provider === 'pve' ? t('Simulierte PVE-Task-Referenz', 'Simulated PVE task reference')
      : t('Simulierte Executor-Referenz', 'Simulated executor reference');
    const controls = (runtimeActions[stage] || []).map((action, index) =>
      `<button type="button" class="button${index === 0 ? ' primary' : ''}" data-runtime-action="${action}"
        ${busy ? 'disabled' : ''}>${t(...runtimeActionLabels[action])}</button>`).join('');
    return `<section class="manage-decision" aria-labelledby="runtime-job-title" data-runtime-review="${escape(id)}"
      data-runtime-revision="${escape(revision)}" aria-busy="${busy}">
      <h3 id="runtime-job-title">${t('Laufzeitauftrag', 'Runtime job')}</h3>
      <dl class="manage-job-meta">
        <div><dt>${t('Ausgangszustand', 'Initial state')}</dt><dd>${escape(before)}</dd></div>
        <div><dt>${t('Zielzustand', 'Target state')}</dt><dd>${escape(after)}</dd></div>
        <div><dt>${t('Zuletzt im Auftrag beobachtet', 'Last observed in the job')}</dt><dd>${escape(observed)}</dd></div>
        <div><dt>${t('Ausführungsquelle', 'Execution source')}</dt><dd>${source}</dd></div>
        <div><dt>${t('Auftragsrevision', 'Job revision')}</dt><dd>${escape(revision)}</dd></div>
        ${taskId ? `<div><dt>${reference}</dt><dd>${escape(taskId)}</dd></div>` : ''}
        ${attemptedAt ? `<div><dt>${t('Ausführung angefordert', 'Execution requested')}</dt><dd><time datetime="${escape(attemptedAt)}">${escape(formatJobTime(attemptedAt))}</time></dd></div>` : ''}
      </dl>
      <div class="service-tools">
        ${controls}
        <button type="button" class="text-button" data-view="events" data-host="${escape(job.host)}"
          data-event-kind="runtime" data-event-subject="service:${escape(job.serviceId)}">${t('Laufzeitereignisse öffnen', 'Open runtime events')}</button>
      </div>
      <p data-runtime-notice role="status" tabindex="-1">${escape(runtimeFeedback.get(id) || '')}</p>
    </section>`;
  }

  function adapterSettingsJob(item) {
    const at = formatJobTime(item.at);
    return {
      id: item.id, serviceId: item.serviceId, host: item.host, time: at, at: item.at,
      title: `${item.name} · Einstellungen`, type: 'Adapter-Einstellungen', status: item.status, tone: 'active',
      target: `${item.name} auf ${item.host}`, actor: 'Betreiber · Demo',
      context: 'Der Adapter prüft das Eingabeschema vor dem Speichern des Entwurfs.',
      outcome: item.status, verification: 'Im Browser gespeichert',
      adapter: item.adapterVersion && Array.isArray(item.changes)
        ? { version: item.adapterVersion, revision: item.adapterRevision, changes: item.changes } : null,
      events: [[at, 'Schema geprüft', 'Die Felder passen zur Adapterversion des Dienstes.'],
        [at, 'Entwurf gespeichert', 'Die Betriebseinstellungen des Beispieldienstes sind im Inventar sichtbar.']],
    };
  }

  function adapterTransitionJob(item) {
    const at = formatJobTime(item.at);
    const operation = item.action === 'rollback' ? 'Adapter zurücksetzen' : 'Adapter aktualisieren';
    return {
      id: item.id, serviceId: item.serviceId, host: item.host, time: at, at: item.at,
      title: `${item.name} · ${operation}`, type: 'Adapter-Wechsel', status: item.status, tone: 'active',
      target: `${item.name} auf ${item.host}`, actor: 'Betreiber · Demo',
      context: 'Die Vorschau bindet den Adapter-Wechsel an die zuvor angezeigte Konfigurationsrevision.',
      outcome: item.status, verification: 'Browser-Simulation · im lokalen Beispielinventar gespeichert',
      adapterTransition: { from: item.from, to: item.to, rows: item.rows },
      events: [[at, 'Vorschau bestätigt', operation],
        [at, 'Adapter und Konfiguration gespeichert', 'Der Dienst zeigt die neue Revision im Beispielinventar.']],
    };
  }

  function networkPortJob(item) {
    const at = formatJobTime(item.at);
    return {
      id: item.id, portId: item.portId, host: item.host ?? '', time: at, at: item.at,
      title: `${item.name} · VLAN-Zuordnung`, type: 'Netzwerkänderung', status: item.status, tone: 'active',
      target: item.name, actor: 'Betreiber · Demo',
      context: 'Die bestätigte Vorschau erfasst Portmodus, natives VLAN und getaggte VLANs.',
      outcome: item.status, verification: 'Demo-Readback · Konfiguration im Beispielinventar gespeichert',
      portChange: { before: item.before, after: item.after, revision: item.revision },
      events: [[at, 'Vorschau bestätigt', 'Die Änderung ist an die gewählte Portrevision gebunden.'],
        [at, 'Demo-Readback', 'Der Browser hat die gespeicherte Portkonfiguration gelesen. Eine Verkehrsprobe steht aus.']],
    };
  }

  function networkRuleJob(state, change) {
    const { id, ruleId, host, name, nameEn, before, after, revision, status, requestedAt, decidedAt } = change;
    const rule = window.opstendNetworkRules.get(state, ruleId);
    const source = state.inventory.services.find((item) => item.id === rule?.sourceId);
    const title = t(name, nameEn || name);
    const pending = status === 'pending';
    const applied = status === 'applied';
    const outcome = pending ? t('Freigabe steht aus', 'Approval pending')
      : applied ? t('Netzregel in der Demo übernommen', 'Network rule applied in the demo') : t('Regeländerung abgelehnt', 'Rule change rejected');
    const context = t('Die Vorschau bindet Regelwirkung und Ausgangsrevision an diesen Auftrag.',
      'The preview binds the rule action and base revision to this job.');
    const verification = applied ? t(`Im Browser gespeichert · Revision ${revision + 1}`, `Saved in this browser · revision ${revision + 1}`)
      : pending ? t('Vorschau gespeichert', 'Preview saved') : t('Entscheidung im Browser gespeichert', 'Decision saved in this browser');
    const events = [[formatJobTime(requestedAt), t('Regeländerung vorgemerkt', 'Rule change submitted'),
      `${ruleEffect(before)} → ${ruleEffect(after)} · ${t('Ausgangsrevision', 'Base revision')} ${revision}`, requestedAt]];
    if (pending) events.push(['Ausstehend', t('Betreiberfreigabe', 'Operator approval'), context]);
    else if (decidedAt) events.push([formatJobTime(decidedAt), outcome, applied
      ? `${t('Bestätigte Regelwirkung', 'Approved action')} · ${ruleEffect(after)} · ${t('Revision', 'Revision')} ${revision + 1}`
      : `${t('Abgelehnter Vorschlag', 'Rejected proposal')} · ${ruleEffect(after)} · ${t('Ausgangsrevision', 'Base revision')} ${revision}`, decidedAt]);
    return {
      id, ruleId, host, ...(source ? { serviceId: source.id } : {}), ...(rule?.linkId ? { linkId: rule.linkId } : {}),
      title, ruleName: title, type: 'Netzwerkänderung', time: formatJobTime(decidedAt || requestedAt), at: decidedAt || requestedAt,
      status: pending ? t('Wartet auf Freigabe', 'Awaiting approval') : outcome,
      tone: pending ? 'warn' : applied ? 'success' : 'active',
      target: title, actor: t('Betreiber · Demo', 'Operator · demo'), context, outcome, verification, events, ruleChange: change,
      attention: pending ? { kind: 'decision', title, status: t('Deine Freigabe ist gefragt', 'Your approval is needed'),
        impact: `${t('Regelwirkung', 'Rule action')} · ${ruleEffect(before)} → ${ruleEffect(after)}`,
        action: t('Netzregel prüfen', 'Review network rule') } : null,
    };
  }

  function networkRuleJobs(state) {
    return (window.opstendNetworkRules?.records(state) || []).map((change) => networkRuleJob(state, change));
  }

  const maintenanceStages = {
    pending: ['Wartet auf Freigabe', 'Awaiting approval', 'warn', 'Vorschau gespeichert', 'Preview saved'],
    approved: ['Freigegeben', 'Approved', 'active', 'Freigabe für das geplante Fenster gespeichert.', 'Approval saved for the scheduled window.'],
    rejected: ['Abgelehnt', 'Rejected', 'active', 'Entscheidung im Browser gespeichert', 'Decision saved in this browser'],
    active: ['Wartung läuft', 'Maintenance in progress', 'active', 'Betroffene Gäste und Dienste pausieren in der Demo.', 'Affected guests and services are paused in the demo.'],
    finished: ['Wiederanlauf simuliert', 'Recovery simulated', 'success', 'Die Health-Prüfung der gestarteten Dienste steht aus.', 'Health checks are pending for restarted services.'],
  };
  const maintenanceEvents = {
    request: ['Wartung vorgemerkt', 'Maintenance submitted', 'Termin und Auswirkung je Dienst gespeichert.', 'Saved the date and impact for each service.'],
    approve: ['Wartung freigegeben', 'Maintenance approved', 'Die Freigabe gilt für das Fenster und die geprüfte Belegung.', 'The approval applies to the window and reviewed workloads.'],
    reject: ['Wartung abgelehnt', 'Maintenance rejected', 'Entscheidung mit Zeitpunkt gespeichert.', 'Saved the decision with its timestamp.'],
    start: ['Neustart simuliert', 'Restart simulated', 'Der Host ist in Wartung. Die Simulation hält die betroffenen Dienste an.', 'The host is in maintenance. The simulation pauses the affected services.'],
    finish: ['Wiederanlauf simuliert', 'Recovery simulated', 'Die Simulation hat die verfügbaren Dienste wieder gestartet. Die Health-Prüfung steht aus.', 'The simulation restarted available services. Health checks are pending.'],
  };

  function hostMaintenanceJob(record) {
    const { id, host, stage, window: slot, workloads } = record;
    const [statusDe, statusEn, tone, verificationDe, verificationEn] = maintenanceStages[stage];
    const canceled = stage === 'rejected' && record.events.some(({ action }) => action === 'approve');
    const status = canceled ? t('Abgesagt', 'Canceled') : t(statusDe, statusEn);
    const affected = workloads.filter(({ handling }) => handling === 'restart').length;
    const restartComplete = t('Der simulierte Neustart des Hosts ist beendet.', 'The simulated host restart is complete.');
    const at = record.events.at(-1)?.at;
    const context = t('Der Auftrag bindet einen geplanten Neustart an den Host, das Wartungsfenster und die geprüfte Belegung.',
      'This job binds a planned restart to the host, maintenance window, and reviewed workloads.');
    const events = record.events.map(({ action, at: timestamp, actor }) => {
      const [titleDe, titleEn, detailDe, detailEn] = maintenanceEvents[action];
      const title = canceled && action === 'reject' ? t('Wartung abgesagt', 'Maintenance canceled') : t(titleDe, titleEn);
      const detail = action === 'approve' && actor === 'zorec'
        ? t('Zorec hat die geprüfte Planung für das Wartungsfenster freigegeben.', 'Zorec approved the reviewed plan for the maintenance window.')
        : action === 'finish' && affected === 0 ? restartComplete : t(detailDe, detailEn);
      return [formatJobTime(timestamp), title, detail, timestamp, undefined, maintenanceActor(actor)];
    });
    if (stage === 'pending') events.push(['Ausstehend', t('Betreiberfreigabe', 'Operator approval'), context]);
    const impact = affected === 1 ? t('Eine Instanz wird unterbrochen', 'One instance will be interrupted')
      : t(`${affected} Instanzen werden unterbrochen`, `${affected} instances will be interrupted`);
    return {
      id, host, at, time: formatJobTime(at), title: t(`Hostwartung · ${host}`, `Host maintenance · ${host}`), type: 'Hostwartung', status, tone,
      target: host, actor: maintenanceActor(record.events[0]?.actor), context, outcome: status,
      verification: stage === 'finished' && affected === 0 ? restartComplete : t(verificationDe, verificationEn), events, maintenance: record,
      attention: stage === 'pending' ? {
        kind: 'decision', title: t(`Wartung auf ${host}`, `Maintenance on ${host}`),
        impact: `${impact} · ${t(slot.label, slot.labelEn)}`,
        status: t('Deine Freigabe ist gefragt', 'Your approval is needed'), action: t('Wartung prüfen', 'Review maintenance'),
      } : null,
    };
  }

  function hostMaintenanceJobs(state) {
    return (window.opstendHostMaintenance?.records(state) || []).map(hostMaintenanceJob);
  }

  function guestProvisionJob(item) {
    const { provisioning } = item;
    const { plannedAt, readbackAt, start, templateTitle } = provisioning;
    const pending = !readbackAt && item.status === 'Vorgemerkt';
    const initialState = start ? 'Läuft' : 'Gestoppt';
    const events = [[formatJobTime(plannedAt), 'Anlage vorgemerkt',
      `${templateTitle} und das Ziel ${item.host} sind im Entwurf festgelegt.`, plannedAt]];
    if (readbackAt) {
      events.push([formatJobTime(readbackAt), 'Demo-Readback',
        `Der Browser hat die simulierte Gastanlage mit dem Laufzustand „${initialState}“ gelesen.`, readbackAt]);
    } else if (pending) {
      events.push(['Ausstehend', 'Demo-Readback', 'Die Rückmeldung der Gastanlage steht aus.']);
    }
    return {
      id: `guest-${item.id}`, serviceId: item.id, host: item.host, time: formatJobTime(readbackAt || plannedAt),
      title: `${item.name} anlegen`, type: 'Gastanlage', tone: readbackAt ? 'success' : 'active',
      status: readbackAt ? 'Abgeschlossen' : pending ? 'Vorgemerkt' : item.status,
      target: `${item.name} · ${item.kind}`, actor: 'Betreiber · Demo',
      context: 'Die Simulation speichert Platzierung und Ressourcen des Gasts im Browserinventar.',
      outcome: readbackAt ? 'Gast im Demo-Inventar angelegt' : pending ? 'Anlage vorgemerkt' : item.status,
      verification: readbackAt ? `Demo-Readback · ${initialState}` : pending ? 'Rückmeldung steht aus' : 'Aktuellen Zustand am Gast ansehen',
      guest: item, provisionPending: pending, events,
    };
  }

  function projectJobs(state) {
    const guestJobs = state.inventory.services.filter((item) => item.provisioning).map(guestProvisionJob);
    const newJobs = state.inventory.services.filter((item) => item.status === 'Vorgemerkt' && !item.provisioning).map((item) => ({
      id: `service-${item.id}`, serviceId: item.id, host: item.host, time: 'Demo', title: `${item.name} anlegen`,
      type: 'Dienst-Deployment', status: 'Vorgemerkt', tone: 'active',
      target: `${item.name} · ${item.kind}`, actor: 'Betreiber · Demo',
      context: `${item.repositories.length} Repository-Quellen. Ziel, Adapter und Update-Richtlinie sind im Entwurf gebunden.`,
      outcome: 'Deployment-Vorschau bestätigt', verification: 'Beispielauftrag · steht zur Ausführung bereit',
      events: [['Demo', 'Quellen gewählt', 'Die Repository-Liste gehört zum Auftrag.'],
        ['Demo', 'Dienstvertrag bestätigt', 'Host, Netzwerk und Adapter sind festgelegt.'],
        ['Ausstehend', 'Build, Validierung und Readback', 'Die Vorschau zeigt den vorgesehenen Ausführungspfad.']],
    }));
    const localJobs = state.inventory.changes.filter((item) => item.id !== routeDecisionId).map((item) => {
      if (item.kind === 'host-enrollment') return {
        id: item.id, host: item.host, relatedHost: item.relatedHost, time: formatJobTime(item.at), at: item.at,
        title: item.name, type: 'Hostverwaltung', status: item.status, tone: 'success', target: item.host, actor: 'OpsTend · Demo',
        context: 'Die Hostverwaltung hat die geprüfte Vorschau und die Entscheidung je Dienst im Browser gespeichert.',
        outcome: item.status, verification: 'Beispielinventar abgeglichen', hostEnrollment: true,
        events: [[formatJobTime(item.at), item.status, item.host, item.at],
          ...item.services.map((service) => [formatJobTime(item.at), service.name, service.effect, item.at, {
            serviceId: service.id, serviceName: service.name,
            relatedHost: service.action === 'migrate' ? item.relatedHost : undefined,
          }])],
      };
      if (item.kind === 'runtime') return runtimeJob(item);
      if (item.kind === 'service-config') return adapterSettingsJob(item);
      if (item.kind === 'service-adapter') return adapterTransitionJob(item);
      if (item.kind === 'network-port') return networkPortJob(item);
      return {
        id: item.id, serviceId: item.serviceId || /^(?:retire|remove)-(.+)$/.exec(item.id)?.[1],
        host: item.host, time: 'Demo', title: item.name,
        type: item.id === 'placement-transfer' ? 'Dienstplatzierung' : 'Dienst-Lifecycle',
        status: item.status, tone: 'active', target: item.host,
        actor: 'Betreiber · Demo', context: 'Die Änderung gehört zum lokalen Beispielinventar.',
        outcome: item.status, verification: 'Simulation · Vorschau gespeichert',
        events: [['Demo', 'Vorschau übernommen', 'Die Betriebsansicht verwendet den neuen Beispielzustand.']],
      };
    });
    return [...hostMaintenanceJobs(state), ...networkRuleJobs(state), ...guestJobs, ...newJobs, ...localJobs, ...window.opstendSelfUpdateView.jobs(state), ...exampleJobs(state)];
  }

  function jobEventId(job, index, subject) {
    return subject?.serviceId ? `${job.id}:service:${subject.serviceId}` : `${job.id}:${index}`;
  }

  function jobNavigationHost(state, job, preferred) {
    if (visibleInScope(job, preferred)) return preferred;
    return state.inventory.hosts.some((host) => host.id === job.host) ? job.host : '';
  }

  const jobSummary = ({ id, title, status, time, host, tone }) => ({ id, title, status, time, host, tone });
  const jobsInScope = (state) => projectJobs(state).filter((job) => visibleInScope(job, state.host));
  const selectedJob = (jobs, id) => jobs.find((job) => job.id === id) ?? jobs[0];
  views.selectedJob = (state) => selectedJob(jobsInScope(state), state.job);
  views.jobsForScope = (state) => jobsInScope(state).map(jobSummary);
  views.jobsForService = (state, serviceId) => {
    const host = state.inventory.services.find((service) => service.id === serviceId)?.host || state.host;
    return projectJobs(state).flatMap((job) => {
      const index = job.events.findIndex(([, , , , subject]) => subject?.serviceId === serviceId);
      if (job.serviceId !== serviceId && index === -1 && !job.maintenance?.workloads.some(({ id }) => id === serviceId)) return [];
      return [{ ...jobSummary(job), navigationHost: jobNavigationHost(state, job, host),
        ...(index === -1 ? {} : { jobEvent: jobEventId(job, index, job.events[index][4]) }) }];
    });
  };
  views.jobsForPort = (state, portId) => projectJobs(state)
    .filter((job) => job.portId === portId).map(jobSummary);

  const eventKinds = new Map([
    ['Selbstheilung', 'health'], ['Netzwerkänderung', 'network'],
    ['Adapter-Einstellungen', 'config'], ['Adapter-Wechsel', 'config'],
    ['Gastverwaltung', 'runtime'], ['Laufzeit', 'runtime'],
    ['Dienstplatzierung', 'runtime'], ['Dienst-Lifecycle', 'runtime'],
    ['Hostwartung', 'maintenance'],
    ['Dienst-Deployment', 'deployment'], ['Gastanlage', 'deployment'], ['OpsTend-Eigenupdate', 'deployment'], ['Hostverwaltung', 'deployment'],
  ]);

  views.eventsForScope = (state) => {
    const dated = [];
    const clockTimes = [];
    const undated = [];
    const selectedService = state.eventSubject?.startsWith('service:') ? state.eventSubject.slice('service:'.length) : '';
    const serviceHistory = state.host && state.inventory.services.some((service) =>
      service.id === selectedService && service.host === state.host);
    for (const job of projectJobs(state)) {
      for (let index = job.events.length - 1; index >= 0; index -= 1) {
        const [time, title, detail, at = job.at, subject, actor = job.actor] = job.events[index];
        if (time === 'Läuft' || time === 'Ausstehend') continue;
        const serviceId = subject?.serviceId || job.serviceId;
        const relatedHost = subject ? subject.relatedHost : job.relatedHost;
        const inScope = visibleInScope({ host: job.host, relatedHost }, state.host);
        if (!inScope && !(serviceHistory && serviceId === selectedService)) continue;
        const event = {
          id: jobEventId(job, index, subject), jobId: job.id, title, detail,
          kind: eventKinds.get(job.type) ?? 'other', time, host: job.host ?? '', actor,
          display: { title: exampleJobText(job, title), detail: exampleJobText(job, detail), actor: jobText(actor) },
          navigationHost: jobNavigationHost(state, job, state.host),
          ...(serviceId ? { serviceId } : {}),
          ...(subject?.serviceName ? { serviceName: subject.serviceName } : {}),
          ...(job.hostEnrollment && relatedHost ? { relatedHost } : {}),
          ...(job.portId ? { portId: job.portId } : {}),
          ...(job.ruleId ? { ruleId: job.ruleId, ruleName: job.ruleName } : {}),
        };
        const timestamp = /^\d{4}-\d{2}-\d{2}T/.test(at) ? Date.parse(at) : NaN;
        if (Number.isFinite(timestamp)) dated.push({ event: { ...event, at }, timestamp });
        else if (/^\d{2}:\d{2}:\d{2}$/.test(time)) clockTimes.push(event);
        else undated.push(event);
      }
    }
    dated.sort((first, second) => second.timestamp - first.timestamp);
    clockTimes.sort((first, second) => second.time.localeCompare(first.time));
    return [...dated.map(({ event }) => event), ...clockTimes, ...undated];
  };

  views.changes = (state) => {
    const { escape } = state;
    const host = state.hosts[state.host]?.name;
    const visibleJobs = jobsInScope(state);
    const selected = selectedJob(visibleJobs, state.job);
    const pending = visibleJobs.filter((job) => job.attention?.kind === 'decision' || job.nextDecision?.kind === 'decision').length;
    const statusText = pending === 0 ? t('Keine Freigabe ausstehend', 'No pending approvals')
      : pending === 1 ? t('1 Freigabe ausstehend', '1 pending approval') : t(`${pending} Freigaben ausstehend`, `${pending} pending approvals`);
    const jobButtons = visibleJobs.map((job) => `<button type="button" class="manage-job" data-job="${escape(job.id)}" aria-pressed="${String(job === selected)}">
      <span class="manage-job-icon manage-tone-${job.tone}" aria-hidden="true">${job.tone === 'success' ? '✓' : '◷'}</span>
      <span class="manage-job-name"><strong>${escape(exampleJobText(job, job.title))}</strong><small>${job.host ? `${escape(job.host)} · ` : ''}${escape(jobText(job.type))}</small>
      <span class="manage-job-status manage-tone-${job.tone}">${escape(jobText(job.status))}</span></span>
      <time>${escape(job.time)}</time>
    </button>`).join('');

    return `<div class="manage-screen">
      <header class="page-intro split"><div><h1>${t('Änderungen', 'Changes')}</h1>
        <p>${host ? t(`Aufträge, Freigaben und Automatisierungen für ${escape(host)}.`, `Jobs, approvals, and automations for ${escape(host)}.`)
          : t('Aufträge, Freigaben und Automatisierungen in der gesamten Flotte.', 'Jobs, approvals, and automations across the fleet.')}</p></div>
        <button class="button" type="button" data-view="events">${t('Ereignisprotokoll öffnen', 'Open event log')}</button>
      </header>
      <div class="manage-layout">
        <section class="panel manage-jobs" aria-label="${t('Auftragsliste', 'Job list')}">
          <div class="manage-panel-heading"><div><h2 id="manage-jobs-title" tabindex="-1">${t('Aufträge', 'Jobs')}</h2>
            <p>${visibleJobs.length} ${t('Einträge', visibleJobs.length === 1 ? 'entry' : 'entries')} · ${statusText}</p></div></div>
          ${jobButtons || `<p class="manage-description">${t('Für diesen Host liegt kein Auftrag vor.', 'This host has no jobs.')}</p>`}
        </section>
        ${changeDetail(state, selected)}
      </div>
    </div>`;
  };

  async function decideNetworkRule(button) {
    const review = button.closest('[data-network-rule-review]');
    if (!review) return;
    const id = review.dataset.networkRuleReview;
    if (decidingRules.has(id)) return;
    const state = { host: review.dataset.networkRuleReviewHost, inventory: window.opstendDemo.getInventory() };
    decidingRules.add(id);
    ruleDecisionFeedback.delete(id);
    review.setAttribute('aria-busy', 'true');
    for (const control of review.querySelectorAll('[data-network-rule-decision]')) control.disabled = true;
    try {
      const result = await window.opstendNetworkRules.decide(state, id, button.dataset.networkRuleDecision);
      if (!result.ok) ruleDecisionFeedback.set(id, result.error);
    } catch {
      ruleDecisionFeedback.set(id, t('Die Entscheidung konnte nicht gespeichert werden.', 'The decision could not be saved.'));
    } finally {
      decidingRules.delete(id);
    }
    const failed = ruleDecisionFeedback.has(id);
    if (failed) window.dispatchEvent(new Event('opstend:network-rules-changed'));
    const current = document.querySelector('[data-network-rule-review]');
    if (current?.dataset.networkRuleReview !== id) return;
    const focus = failed ? current.querySelector('[data-network-rule-notice]')
      : current.closest('.manage-job-detail')?.querySelector('.manage-outcome');
    focus?.focus({ preventScroll: true });
  }

  async function advanceHostMaintenance(button) {
    const review = button.closest('[data-host-maintenance-review]');
    if (!review) return;
    const { hostMaintenanceReview: id, hostMaintenanceScope: host } = review.dataset;
    const revision = Number(review.dataset.hostMaintenanceRevision);
    if (advancingMaintenance.has(id)) return;
    const state = { host, inventory: window.opstendDemo.getInventory() };
    advancingMaintenance.set(id, revision);
    maintenanceFeedback.delete(id);
    review.setAttribute('aria-busy', 'true');
    for (const control of review.querySelectorAll('[data-host-maintenance-action]')) control.disabled = true;
    try {
      const result = await window.opstendHostMaintenance.advance(state, id, button.dataset.hostMaintenanceAction, revision);
      if (!result.ok) maintenanceFeedback.set(id, t(result.error, result.errorEn ?? result.error));
    } catch {
      maintenanceFeedback.set(id, t('Der Wartungsschritt konnte nicht gespeichert werden.', 'The maintenance step could not be saved.'));
    } finally {
      advancingMaintenance.delete(id);
    }
    const failed = maintenanceFeedback.has(id);
    if (failed) window.dispatchEvent(new Event('opstend:host-maintenance-changed'));
    const current = document.querySelector('[data-host-maintenance-review]');
    if (current?.dataset.hostMaintenanceReview !== id) return;
    const focus = failed ? current.querySelector('[data-host-maintenance-notice]')
      : current.closest('.manage-job-detail')?.querySelector('.manage-outcome');
    focus?.focus({ preventScroll: true });
  }

  async function advancePublication(button) {
    const review = button.closest('[data-publication-review]');
    if (!review) return;
    const { publicationReview: id, publicationScope: host, publicationBinding: binding } = review.dataset;
    const revision = Number(review.dataset.publicationRevision);
    if (advancingPublications.has(id)) return;
    const state = { host, inventory: window.opstendDemo.getInventory({ fresh: true }) };
    advancingPublications.set(id, revision);
    publicationFeedback.delete(id);
    review.setAttribute('aria-busy', 'true');
    for (const control of review.querySelectorAll('[data-publication-action]')) control.disabled = true;
    try {
      const result = await window.opstendPublications.advance(state, id, button.dataset.publicationAction, revision, binding);
      if (!result.ok) publicationFeedback.set(id, t(result.error, result.errorEn ?? result.error));
    } catch {
      publicationFeedback.set(id, t('Die Veröffentlichung konnte nicht gespeichert werden.', 'The publication could not be saved.'));
    } finally {
      advancingPublications.delete(id);
    }
    const failed = publicationFeedback.has(id);
    if (failed) window.dispatchEvent(new Event('opstend:publication-changed'));
    const current = document.querySelector('[data-publication-review]');
    if (current?.dataset.publicationReview !== id) return;
    const focus = failed ? current.querySelector('[data-publication-notice]')
      : current.closest('.manage-job-detail')?.querySelector('.manage-outcome');
    focus?.focus({ preventScroll: true });
  }

  async function advanceRecovery(button) {
    const panel = button.closest('[data-recovery-panel]');
    const detail = panel?.closest('[data-manage-job-detail]');
    if (!detail) return;
    const { recoveryPanel: serviceId, recoveryRevision } = panel.dataset;
    const revision = Number(recoveryRevision);
    if (pendingRecovery.has(serviceId)) return;

    pendingRecovery.set(serviceId, revision);
    panel.setAttribute('aria-busy', 'true');
    for (const control of panel.querySelectorAll('[data-recovery-action]')) control.disabled = true;
    let result;
    try {
      result = await window.opstendDemo.advanceRecovery(serviceId, button.dataset.recoveryAction, revision);
    } catch {
      result = t('Die Nachprüfung konnte nicht gespeichert werden.', 'The follow-up check could not be saved.');
    } finally {
      pendingRecovery.delete(serviceId);
    }

    const current = document.querySelector('[data-manage-job-detail]');
    if (current?.dataset.manageJobDetail !== detail.dataset.manageJobDetail) return;
    if (result === true) {
      current.querySelector('.manage-outcome')?.focus({ preventScroll: true });
      return;
    }
    const currentPanel = current.querySelector('[data-recovery-panel]');
    if (!currentPanel) return;
    currentPanel.setAttribute('aria-busy', 'false');
    for (const control of currentPanel.querySelectorAll('[data-recovery-action]')) control.disabled = false;
    const notice = currentPanel.querySelector('#recovery-notice');
    notice.textContent = jobText(result);
    notice.focus({ preventScroll: true });
  }

  async function advanceRuntime(button) {
    const review = button.closest('[data-runtime-review]');
    if (!review) return;
    const id = review.dataset.runtimeReview;
    if (advancingRuntime.has(id)) return;
    const revision = Number(review.dataset.runtimeRevision);
    advancingRuntime.set(id, revision);
    runtimeFeedback.delete(id);
    review.setAttribute('aria-busy', 'true');
    for (const control of review.querySelectorAll('[data-runtime-action]')) control.disabled = true;
    try {
      const result = await window.opstendDemo.advanceRuntime(id, button.dataset.runtimeAction, revision);
      if (!result.ok) runtimeFeedback.set(id, t(result.error, result.errorEn ?? result.error));
    } catch {
      runtimeFeedback.set(id, t('Der Auftragsschritt konnte nicht gespeichert werden.', 'The job step could not be saved.'));
    } finally {
      advancingRuntime.delete(id);
    }
    const failed = runtimeFeedback.has(id);
    if (failed) window.dispatchEvent(new Event('opstend:inventory-changed'));
    const current = document.querySelector('[data-runtime-review]');
    if (current?.dataset.runtimeReview !== id) return;
    const focus = failed ? current.querySelector('[data-runtime-notice]')
      : current.closest('.manage-job-detail')?.querySelector('.manage-outcome');
    focus?.focus({ preventScroll: true });
  }

  document.addEventListener('click', (event) => {
    const runtime = event.target.closest('button[data-runtime-action]');
    if (runtime) {
      void advanceRuntime(runtime);
      return;
    }
    const publication = event.target.closest('button[data-publication-action]');
    if (publication) {
      void advancePublication(publication);
      return;
    }
    const maintenance = event.target.closest('button[data-host-maintenance-action]');
    if (maintenance) {
      void advanceHostMaintenance(maintenance);
      return;
    }
    const rule = event.target.closest('button[data-network-rule-decision]');
    if (rule) {
      void decideNetworkRule(rule);
      return;
    }
    const guest = event.target.closest('button[data-guest-provision-confirm]');
    if (guest) {
      const result = window.opstendDemo.finishGuestProvision(guest.dataset.guestProvisionConfirm);
      if (result !== true) {
        document.getElementById('guest-provision-notice').textContent = result;
        return;
      }
      window.dispatchEvent(new CustomEvent('opstend:inventory-changed'));
      document.querySelector('.manage-job-detail .manage-outcome')?.focus({ preventScroll: true });
      return;
    }
    const button = event.target.closest('button[data-recovery-action]');
    if (button) void advanceRecovery(button);
  });

  function policyTable(host) {
    const edge = host === 'edge-01';
    const primary = host === 'host-b';
    const slot = window.opstendHostMaintenance.windowFor(host);
    const migrationValue = primary || edge ? 'Für diesen Host nicht verfügbar' : 'Freigabe erforderlich';
    return `<section class="panel manage-policies" aria-label="Wirksame Richtlinien">
      <div class="manage-panel-heading"><div><h2>Wirksame Richtlinien</h2><p>Zeitzone Europe/Berlin</p></div></div>
      <div class="manage-table-wrap"><table class="manage-table">
        <thead><tr><th scope="col">Einstellung</th><th scope="col">Wirksamer Wert</th><th scope="col">Herkunft</th></tr></thead>
        <tbody>
          <tr><th scope="row">${t('Wartungsfenster', 'Maintenance window')}</th><td>${t(slot.label, slot.labelEn)}</td><td>${t(slot.source, slot.sourceEn)}</td></tr>
          <tr><th scope="row">Selbstheilung</th><td>Ein Neustart je Störung</td><td>Flotte</td></tr>
          <tr><th scope="row">Öffentliche Freigabe</th><td>Bestätigung erforderlich</td><td>Flotte</td></tr>
          <tr><th scope="row">Proxmox-Migration</th><td>${migrationValue}</td><td>${primary || edge ? 'Host-Fähigkeiten' : 'Flotte'}</td></tr>
        </tbody>
      </table></div>
      <div class="manage-settings-note"><strong>Außerhalb des Wartungsfensters</strong><p>Die Vorschau einer geplanten Änderung zeigt die nächste zulässige Ausführungszeit.</p></div>
    </section>`;
  }

  function policyScope(host) {
    const edge = host === 'edge-01';
    const fleetSlot = window.opstendHostMaintenance.windowFor('');
    const edgeSlot = window.opstendHostMaintenance.windowFor('edge-01');
    const scopeValue = host ? `<strong>${host}</strong><small>${edge ? 'Eigenes Wartungsfenster' : 'Übernimmt die gemeinsamen Vorgaben'}</small>` : '<strong>Ein Host mit Ausnahme</strong><small>edge-01 · eigenes Wartungsfenster</small>';
    return `<aside class="panel manage-scope-detail" aria-label="Richtlinienherkunft">
      <div class="manage-panel-heading"><div><h2>Woher der Wert kommt</h2><p>Beispiel · Wartungsfenster</p></div></div>
      <ol class="manage-inheritance">
        <li><strong>Flottenvorgabe</strong><small>${t(fleetSlot.label, fleetSlot.labelEn)}</small></li>
        <li><strong>${edge ? 'Standort · Extern' : host ? 'Standort · Werkstatt' : 'Standorte'}</strong><small>Übernehmen die Flottenvorgabe</small></li>
        <li>${scopeValue}</li>
      </ol>
      ${edge || !host ? `<div class="manage-settings-note"><strong>Ausnahme für edge-01</strong><p>${t(edgeSlot.label, edgeSlot.labelEn)} · Europe/Berlin</p></div>` : ''}
      ${host ? '<button class="button" data-view="host">Host ansehen</button>' : ''}
    </aside>`;
  }

  const settingsContent = {
    integrations: {
      title: 'Anschlüsse und Basisdienste',
      columns: ['Anschluss', 'Quelle', 'Status'],
      items: [
        ['Proxmox VE', 'nuc-a', 'Leseinventar · PX02-Demo'],
        ['Podman', 'host-b', 'Beispielinventar · Linux-Agent in RC2'],
        ['UniFi Cloud Gateway', 'Werkstatt', 'Beispieldaten · Leseadapter in RC2'],
        ['Benutzer und Gruppen', 'Flotte', 'OIDC-Anbieter · vorgesehen'],
        ['DNS und Zertifikate', 'Flotte', 'Interne Dienste und ACME · vorgesehen'],
        ['Zeitsynchronisation', 'host-b', 'Beispieldaten · chrony'],
      ],
      note: 'Der spätere Verbindungsdialog zeigt pro Anschluss die angebotenen Abfragen und Aktionen.',
    },
    backup: {
      title: 'Sicherung und Wiederherstellung',
      columns: ['Ziel', 'Quelle', 'Stand'],
      items: [
        ['PBS', 'nuc-a', 'Sicherung der Proxmox-Gäste'],
        ['Pi-NAS', 'Werkstatt', 'NFS-Freigabe · erreichbar'],
        ['Restic', 'host-b', 'Sicherung von Anwendungsdaten'],
        ['Cloud-Ziele', 'Flotte', 'Anbieterprüfung vorgesehen'],
      ],
      note: 'Pro Ziel werden Sicherung, Kopie und bestätigte Wiederherstellung einzeln angezeigt.',
    },
    features: {
      title: 'Funktionen und Voraussetzungen',
      columns: ['Funktion', 'Geltungsbereich', 'Wirksamer Stand'],
      items: [
        ['Dienst-Deployment', 'Flotte', 'Vorschau · Ziel und Adapter bestätigen'],
        ['Automatische Git-Updates', 'Flotte', 'Je Dienst über Update-Richtlinie'],
        ['Topologie ändern', 'Flotte', 'Demo-Entwurf im Beispielinventar'],
        ['Nativen PVE-Gast steuern', 'nuc-a', 'RC2 · native PVE-API'],
        ['Podman-Dienst', 'host-b', 'RC2 · Podman-Referenzprofil'],
        ['UniFi-Konfiguration schreiben', 'Flotte', 'RC2 · ausgewählte Änderungen und Readback'],
        ['Externes Portal', 'edge-01', 'RC2 · zielgebundene Freigabe'],
      ],
      note: 'Die Freigabe wirkt auf den gewählten Dienst, die Maschine und die Rolle.',
    },
    placement: {
      title: 'Platzierung zentraler Dienste',
      columns: ['Rolle', 'Quelle', 'Belegung'],
      note: 'Die Platzierung berücksichtigt verfügbare Kapazität, Gerätebindung und gemeinsame Ausfalldomänen.',
    },
  };

  function settingsTable(tab, host, state) {
    const section = settingsContent[tab];
    const headings = section.columns.map((column) => `<th scope="col">${column}</th>`).join('');
    const all = section.items ?? state.inventory.services.filter((item) => item.role !== 'Anwendung')
      .map((item) => [item.name, item.host, item.instance ?? item.status]);
    const items = host ? all.filter(([, source]) => source === host || source === 'Flotte' || source === state.hosts[host].site) : all;
    const rows = items.map(([label, source, status]) => `<tr><th scope="row">${state.escape(label)}</th><td>${state.escape(source)}</td><td>${state.escape(status)}</td></tr>`).join('');
    return `<section class="panel manage-policies" aria-label="${section.title}">
      <div class="manage-panel-heading"><div><h2>${section.title}</h2><p>${host ?? 'Ganze Flotte'}</p></div>
        ${tab === 'integrations' ? window.opstendPveInventoryUI?.link(state) ?? '' : ''}</div>
      ${rows ? `<div class="manage-table-wrap"><table class="manage-table"><thead><tr>${headings}</tr></thead><tbody>${rows}</tbody></table></div>` : '<p class="manage-description">Für diesen Host gibt es im Beispiel keine Einträge.</p>'}
      <div class="manage-settings-note"><p>${section.note}</p></div>
    </section>`;
  }

  function backupSetup(state) {
    return `<section class="panel manage-scope-detail" aria-label="Backup-Ziel verbinden">
      <div class="manage-panel-heading"><div><h2>Backup-Ziel entwerfen</h2></div></div>
      <form id="demo-backup-form" class="manage-form">
        <label for="backup-protocol">Zieltyp</label>
        <select id="backup-protocol" name="protocol">${['Lokales NAS · SFTP', 'Proxmox Backup Server', 'Restic-Repository']
          .map((name) => `<option ${backupDraft.protocol === name ? 'selected' : ''}>${name}</option>`).join('')}</select>
        <label for="backup-endpoint">Adresse und Pfad</label>
        <input id="backup-endpoint" name="endpoint" required maxlength="160" value="${state.escape(backupDraft.endpoint)}">
        <label for="backup-credential">Keystore-Referenz</label>
        <input id="backup-credential" name="credential" required maxlength="70" value="${state.escape(backupDraft.credential)}">
        <button type="submit" class="button primary">Zielentwurf speichern</button>
        <p id="demo-backup-result" role="status">Verbindungsprüfung und Wiederherstellung folgen im Produkt.</p>
      </form>
    </section>`;
  }

  const accessProfiles = {
    lan: 'Privates LAN',
    loopback: 'Lokal auf dem Host',
    tunnel: 'Privater SSH-Tunnel',
    public: 'Öffentliche Administration',
  };
  let accessDraft = { profile: 'lan', method: 'token', address: '10.20.10.0/24', ttl: '30' };
  let aiDraft = { provider: 'auto', model: '' };
  let demoAiDefaultModel = '';
  let demoAiModels = [];
  let demoAiChecking = false;
  let demoAiDiscovery = 'Verbindung noch nicht geprüft.';
  let demoAiTesting = false;
  let demoAiProbe = '';
  const demoAiComparison = { pair: [], controller: null, progress: null, message: '', report: null };
  const demoAiProviders = [['auto', 'Automatisch'], ['local', 'Lokales Modell'], ['demo', 'Demo-Assistent']];
  let backupDraft = { protocol: 'Lokales NAS · SFTP', endpoint: 'pi-nas:/backups', credential: 'nas-backup' };
  try {
    const saved = JSON.parse(localStorage.getItem('opstend-rc2-configuration') || 'null');
    if (saved?.access) accessDraft = saved.access;
    if (saved?.ai) aiDraft = { ...aiDraft, ...saved.ai };
    if (saved?.backup) backupDraft = { ...backupDraft, ...saved.backup };
  } catch {}
  function persistDrafts() {
    try { localStorage.setItem('opstend-rc2-configuration', JSON.stringify({ access: accessDraft, ai: aiDraft, backup: backupDraft })); } catch {}
  }
  views.demoAiProvider = () => demoAiProviders.some(([id]) => id === aiDraft.provider) ? aiDraft.provider : 'auto';
  views.demoAiModel = () => typeof aiDraft.model === 'string' && aiDraft.model.length <= 160 ? aiDraft.model : '';

  function demoAiModelOptions() {
    const savedModel = views.demoAiModel();
    const models = demoAiModels.map((id) => [id, id]);
    if (savedModel && !demoAiModels.includes(savedModel)) models.push([savedModel, `${savedModel} · gespeichert`]);
    const defaultLabel = demoAiDefaultModel ? `Servervorgabe · ${demoAiDefaultModel}` : 'Servervorgabe';
    return [['', defaultLabel], ...models];
  }

  function demoAiSelection() {
    const provider = views.demoAiProvider();
    if (provider === 'demo' || (provider === 'auto' && !demoAiDefaultModel)) return 'Demo-Assistent';
    if (!demoAiDefaultModel) return 'Lokales Modell · Verbindung nicht eingerichtet';
    return views.demoAiModel() || demoAiDefaultModel;
  }

  function refreshDemoAiSettings() {
    const form = document.getElementById('demo-ai-form');
    if (!form) return;
    form.querySelector('#demo-ai-connection').textContent = window.opstendDemoModel.label();
    form.querySelector('#demo-ai-selected').textContent = demoAiSelection();
    form.querySelector('#demo-ai-discovery').textContent = demoAiDiscovery;
    form.querySelector('#demo-ai-discover').disabled = demoAiChecking;
    form.querySelector('#demo-ai-test').disabled = demoAiTesting || Boolean(demoAiComparison.controller);
    form.querySelector('#demo-ai-probe').textContent = demoAiProbe;
    const model = form.elements.namedItem('model');
    const selection = model.value;
    const options = demoAiModelOptions();
    model.replaceChildren(...options.map(([id, label]) => new Option(label, id)));
    model.value = options.some(([id]) => id === selection) ? selection : views.demoAiModel();
    refreshDemoAiComparison();
  }

  window.addEventListener('opstend:demo-model-config', () => {
    window.opstendDemoModel.status.then(({ model }) => {
      if (typeof model === 'string') demoAiDefaultModel = model;
      refreshDemoAiSettings();
    });
  });

  async function discoverDemoAiModels() {
    if (demoAiChecking) return;
    demoAiChecking = true;
    demoAiDiscovery = 'Verbindung wird geprüft …';
    refreshDemoAiSettings();
    try {
      const { models, activeModel, error } = await window.opstendDemoModel.discover();
      if (error || !Array.isArray(models)) {
        demoAiDiscovery = 'Die Modellliste konnte nicht abgerufen werden.';
        return;
      }
      demoAiModels = [...new Set(models.map((model) => model?.id)
        .filter((id) => typeof id === 'string' && id.length > 0 && id.length <= 160))];
      if (typeof activeModel === 'string') demoAiDefaultModel = activeModel;
      const count = demoAiModels.length;
      demoAiDiscovery = `Verbindung geprüft · ${count} ${count === 1 ? 'Modell' : 'Modelle'} verfügbar.`;
    } catch {
      demoAiDiscovery = 'Die Modellliste konnte nicht abgerufen werden.';
    } finally {
      demoAiChecking = false;
      refreshDemoAiSettings();
    }
  }

  document.addEventListener('click', (event) => {
    if (event.target.closest('#demo-ai-discover')) void discoverDemoAiModels();
    const test = event.target.closest('#demo-ai-test');
    if (test) void testDemoAiModel(test.form.elements.namedItem('model').value);
    if (event.target.closest('#demo-ai-compare-cancel')) {
      demoAiComparison.controller?.abort();
      demoAiComparison.message = 'Der Vergleich endet nach der laufenden Anfrage.';
      refreshDemoAiComparison();
    }
    const candidate = event.target.closest('[data-demo-ai-compare-select]');
    if (candidate && demoAiModels.includes(candidate.dataset.demoAiCompareSelect)) {
      const model = document.getElementById('demo-ai-model');
      model.value = candidate.dataset.demoAiCompareSelect;
      document.getElementById('demo-ai-result').textContent = 'Chat-Modell vorgemerkt. Speichern übernimmt die Auswahl.';
      model.focus();
    }
  });

  async function testDemoAiModel(model) {
    if (demoAiTesting || demoAiComparison.controller) return;
    demoAiTesting = true;
    demoAiProbe = 'Testanfrage läuft …';
    refreshDemoAiSettings();
    const started = performance.now();
    try {
      const result = await window.opstendDemoModel.ask('Antworte mit dem einzelnen Wort BEREIT.', 'Verbindungstest des gewählten Demo-Modells.', [], model);
      const seconds = ((performance.now() - started) / 1000).toLocaleString('de-DE', { maximumFractionDigits: 1 });
      demoAiProbe = result.error || (result.reply.trim() === 'BEREIT' ? `${result.model} · Test bestanden · ${seconds} s`
        : `${result.model} · Antwort erhalten, Prüfvorgabe verfehlt · ${seconds} s`);
    } catch {
      demoAiProbe = 'Der Modelltest konnte gerade nicht abgeschlossen werden.';
    } finally {
      demoAiTesting = false;
      refreshDemoAiSettings();
    }
  }

  function demoAiComparisonPair() {
    if (demoAiModels.length < 2) return ['', ''];
    const available = (model) => demoAiModels.includes(model);
    const [firstDraft, secondDraft] = demoAiComparison.pair;
    const first = available(firstDraft) ? firstDraft : available(demoAiDefaultModel) ? demoAiDefaultModel : demoAiModels[0];
    const second = available(secondDraft) ? secondDraft : demoAiModels.find((id) => id !== first);
    return [first, second];
  }

  function refreshDemoAiComparison() {
    const form = document.getElementById('demo-ai-compare-form');
    if (!form) return;
    const [first, second] = demoAiComparisonPair();
    const running = Boolean(demoAiComparison.controller);
    for (const [name, value] of [['first', first], ['second', second]]) {
      const control = form.elements.namedItem(name);
      control.replaceChildren(...demoAiModels.map((id) => new Option(id, id)));
      control.value = value;
      control.disabled = running || !first;
    }
    form.querySelector('button[type="submit"]').disabled = running || demoAiTesting || !first || first === second;
    const cancel = form.querySelector('#demo-ai-compare-cancel');
    cancel.hidden = !running;
    cancel.disabled = Boolean(demoAiComparison.controller?.signal.aborted);
    const progress = form.querySelector('progress');
    progress.hidden = !running || !demoAiComparison.progress;
    if (demoAiComparison.progress) {
      progress.max = demoAiComparison.progress.total;
      progress.value = demoAiComparison.progress.completed;
    }
    form.querySelector('[role="status"]').textContent = demoAiComparison.message || (!first ? 'Rufe zuerst die Modellliste mit mindestens zwei Modellen ab.'
      : first === second ? 'Wähle zwei unterschiedliche Modelle.' : '');
    for (const action of document.querySelectorAll('[data-demo-ai-compare-select]')) {
      action.disabled = !demoAiModels.includes(action.dataset.demoAiCompareSelect);
    }
  }

  function renderDemoAiComparisonReport() {
    const region = document.getElementById('demo-ai-compare-report');
    const { report } = demoAiComparison;
    if (!region || !report) return;

    function element(tag, label, className = '') {
      const node = document.createElement(tag);
      node.textContent = label;
      node.className = className;
      return node;
    }

    const labels = { passed: ['Korrekt', 'good'], mismatch: ['Abweichung', 'warn'], unavailable: ['Ohne Antwort', ''] };
    const cards = element('div', '', 'model-comparison-results');
    for (const model of report.models) {
      const card = element('article', '', 'model-comparison-card');
      card.append(element('h3', model.id), element('p', `${model.passed} von ${model.total} korrekt`, 'compact'));
      for (const result of model.cases) {
        const details = element('details', '', 'model-comparison-case');
        const heading = element('summary', '');
        const [label, tone] = labels[result.result];
        const seconds = (result.durationMs / 1000).toLocaleString('de-DE', { maximumFractionDigits: 2 });
        heading.append(element('span', result.label), element('span', label, `badge ${tone}`), element('span', `${seconds} s`, 'compact'));
        details.append(heading, element('p', result.reply || result.error || 'Keine Antwort.', 'model-comparison-answer'));
        if (result.expected) details.append(element('p', `Erwartet · ${result.expected}`, 'model-comparison-answer compact'));
        card.append(details);
      }
      if (!model.total) card.append(element('p', 'Keine abgeschlossenen Prüffälle.', 'compact'));
      const transfer = element('button', 'Als Chat-Modell vormerken', 'button');
      transfer.type = 'button';
      transfer.dataset.demoAiCompareSelect = model.id;
      transfer.disabled = !demoAiModels.includes(model.id);
      transfer.setAttribute('aria-label', `${model.id} als Chat-Modell vormerken`);
      card.append(transfer);
      cards.append(card);
    }
    const timestamp = new Date(report.at);
    const time = element('time', timestamp.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }), 'compact');
    time.dateTime = timestamp.toISOString();
    region.replaceChildren(time, cards);
  }

  async function compareDemoAiModels() {
    const pair = demoAiComparisonPair();
    if (demoAiTesting || demoAiComparison.controller || !pair[0] || pair[0] === pair[1]) return;
    const controller = new AbortController();
    Object.assign(demoAiComparison, { controller, progress: null, message: 'Vergleich läuft …' });
    refreshDemoAiSettings();
    try {
      demoAiComparison.report = await window.opstendModelComparison.run(pair, {
        signal: controller.signal,
        onProgress(progress) {
          demoAiComparison.progress = progress;
          if (!controller.signal.aborted) {
            demoAiComparison.message = `${progress.completed} von ${progress.total} Prüffällen abgeschlossen · ${progress.modelId} · ${progress.caseLabel}`;
          }
          refreshDemoAiComparison();
        },
      });
      demoAiComparison.message = demoAiComparison.report.aborted ? 'Vergleich abgebrochen. Die abgeschlossenen Anfragen stehen im Bericht.' : 'Vergleich abgeschlossen.';
      renderDemoAiComparisonReport();
    } catch (error) {
      demoAiComparison.message = error instanceof Error ? error.message : 'Der Modellvergleich konnte nicht abgeschlossen werden.';
    } finally {
      demoAiComparison.controller = null;
      refreshDemoAiSettings();
    }
  }

  function modelComparisonPanel() {
    queueMicrotask(() => {
      renderDemoAiComparisonReport();
      refreshDemoAiComparison();
    });
    return `<section class="panel" aria-labelledby="demo-ai-compare-title">
      <div class="manage-panel-heading"><div><h2 id="demo-ai-compare-title">Modelle vergleichen</h2><p>Identische Prüffragen aus dem Demo-Betrieb</p></div></div>
      <form id="demo-ai-compare-form" class="manage-form">
        <div class="model-comparison-pair">
          <label>Erstes Modell <select name="first" aria-label="Erstes Modell" disabled></select></label>
          <label>Zweites Modell <select name="second" aria-label="Zweites Modell" disabled></select></label>
        </div>
        <div class="service-tools">
          <button class="button" type="submit" disabled>Vergleich starten</button>
          <button class="button" type="button" id="demo-ai-compare-cancel" hidden>Vergleich abbrechen</button>
        </div>
        <progress aria-label="Fortschritt des Modellvergleichs" hidden></progress>
        <p role="status"></p>
      </form>
      <div id="demo-ai-compare-report"></div>
    </section>`;
  }

  function systemSettings(state) {
    const { t } = window.opstendLocale;
    const choices = [['system', t('Systemvorgabe', 'System default')], ['light', t('Hell', 'Light')], ['dark', t('Dunkel', 'Dark')]];
    return `<section class="panel manage-scope-detail" aria-label="${t('Darstellung', 'Appearance')}">
      <div class="manage-panel-heading"><div><h2>${t('Farbschema', 'Color scheme')}</h2>
        <p>${t('Gilt für diesen Browser einschließlich Karte und Zorec.', 'Applies to this browser, including the map and Zorec.')}</p></div></div>
      <div class="service-tools settings-colors">${choices.map(([id, title]) => `
        <button type="button" class="button${id === state.themePreference ? ' primary' : ''}" data-theme-preference="${id}"
          aria-pressed="${id === state.themePreference}">${title}</button>`).join('')}</div>
    </section>`;
  }

  function languageSettings() {
    const locale = window.opstendLocale;
    const { t } = locale;
    const account = locale.profile();
    const shared = account === 'shared';
    const choices = locale.choices();
    const defaults = locale.defaults();
    const names = { de: 'Deutsch', en: 'English' };
    const profiles = [
      ['shared', t('Gemeinsames Konto', 'Shared account')],
      ['oidc', t('Alex · OIDC-Anmeldung', 'Alex · OIDC login')],
      ['local', t('Kim · lokale Anmeldung', 'Kim · local login')],
    ];
    const selection = (field, label, effective) => {
      const languages = Object.entries(names);
      if (!shared) languages.unshift(['inherit', `${t('Standard übernehmen', 'Use shared default')} · ${names[defaults[field]]}`]);
      const origin = choices[field] === 'inherit' || shared
        ? t('Gemeinsamer Standard', 'Shared default') : t('Persönliche Einstellung', 'Personal preference');
      return `<label for="demo-locale-${field}">${label}</label>
        <select id="demo-locale-${field}" name="${field}" aria-describedby="demo-locale-${field}-effective">${optionList(languages, choices[field])}</select>
        <p id="demo-locale-${field}-effective">${t('Aktuell wirksam', 'Currently active')} · ${names[effective]} · ${origin}</p>`;
    };
    return `<section class="panel manage-scope-detail" aria-labelledby="demo-locale-title">
      <div class="manage-panel-heading"><div><h2 id="demo-locale-title">${t('Sprache', 'Language')}</h2>
        <p>${t('Oberfläche und Antworten von Zorec lassen sich getrennt einstellen.', 'The interface and Zorec replies have separate language preferences.')}</p></div></div>
      <div class="manage-form">
        <label for="demo-locale-profile">${t('Demo-Profil', 'Demo profile')}</label>
        <select id="demo-locale-profile" aria-describedby="demo-locale-profile-help">${optionList(profiles, account)}</select>
        <p id="demo-locale-profile-help">${shared
          ? t('Diese Vorgaben gelten für das gemeinsame Konto und für Profile, die sie übernehmen.', 'These defaults apply to the shared account and to profiles that inherit them.')
          : t('Jede persönliche Spracheinstellung gilt für dieses Demo-Profil.', 'Each personal choice applies to this demo profile.')}</p>
      </div>
      <form id="demo-locale-form" class="manage-form">
        ${selection('ui', t('Sprache der Oberfläche', 'Interface language'), locale.ui())}
        ${selection('zorec', t('Antwortsprache von Zorec', 'Zorec reply language'), locale.zorec())}
        <button id="demo-locale-save" class="button primary" type="submit">${t('Spracheinstellungen speichern', 'Save language preferences')}</button>
        <p id="demo-locale-result" role="status"></p>
      </form>
    </section>`;
  }

  document.addEventListener('change', (event) => {
    if (event.target.id !== 'demo-locale-profile') return;
    window.opstendLocale.selectProfile(event.target.value);
    document.getElementById('demo-locale-profile')?.focus({ preventScroll: true });
  });

  document.addEventListener('submit', (event) => {
    if (event.target.id !== 'demo-locale-form') return;
    event.preventDefault();
    const locale = window.opstendLocale;
    const saved = locale.save(Object.fromEntries(new FormData(event.target)));
    const status = document.getElementById('demo-locale-result');
    status.textContent = saved ? locale.t('Spracheinstellungen gespeichert.', 'Language preferences saved.')
      : locale.t('Die Spracheinstellungen konnten hier nicht gespeichert werden.', 'This browser could not save language preferences.');
    document.getElementById('demo-locale-save')?.focus({ preventScroll: true });
  });

  function accessSettings(state) {
    const options = Object.entries(accessProfiles).map(([id, title]) =>
      `<option value="${id}" ${id === accessDraft.profile ? 'selected' : ''}>${title}</option>`
    ).join('');
    return `<div class="manage-layout manage-settings-layout">
      <section class="panel manage-scope-detail">
        <div class="manage-panel-heading"><div><h2>Zugriff auf OpsTend</h2><p>Verwaltungsoberfläche und API</p></div></div>
        <form id="demo-access-form" class="manage-form">
          <label for="demo-access-profile">Zugriffsprofil</label>
          <select id="demo-access-profile" name="profile">${options}</select>
          <label for="demo-access-method">Anmeldemethode</label>
          <select id="demo-access-method" name="method">
            <option value="token" ${accessDraft.method === 'token' ? 'selected' : ''}>Lokales Admin-Token mit Sitzung</option>
            <option value="oidc" ${accessDraft.method === 'oidc' ? 'selected' : ''}>OIDC und MFA</option>
          </select>
          <label for="demo-access-address">Erlaubtes Client-Netz</label>
          <input id="demo-access-address" name="address" maxlength="80" value="${state.escape(accessDraft.address)}" placeholder="10.20.10.0/24">
          <label for="demo-access-ttl">Sitzungsdauer in Minuten</label>
          <input id="demo-access-ttl" name="ttl" type="number" required min="5" max="120" value="${state.escape(accessDraft.ttl)}">
          <button class="button primary" type="submit">Zugriffsänderung prüfen</button>
          <p id="demo-access-result" role="status"></p>
        </form>
      </section>
      <aside class="panel manage-scope-detail">
        <div class="manage-panel-heading"><div><h2>Rollen und Zugriffsmethoden</h2><p>Wirksame Beispielvorgaben</p></div></div>
        <ol class="manage-inheritance">
          <li><strong>Betreiber</strong><small>Registrierte Aktionen mit passender Freigabe</small></li>
          <li><strong>Lesende Rolle</strong><small>Inventar und Beobachtungen im zugewiesenen Bereich</small></li>
          <li><strong>SSH</strong><small>Schlüsselgebundener Host-Zugriff für den Tunnel</small></li>
          <li><strong>Externes Gastportal</strong><small>Separates Login und Freigabe je Ziel</small></li>
        </ol>
      </aside>
    </div>`;
  }

  const reportLevels = { reports: 'Freigegebene Berichte', basic: 'Betriebsübersichten', full: 'Administrativer Leseumfang' };
  const readLevels = [['basic', 'Inventar und Betriebsstatus'], ['full', 'Alle administrativen Lesedaten']];
  const writeLevels = [['draft', 'Entwürfe vorbereiten'], ['operate', 'Betriebsaktionen freigeben'], ['full', 'Vollzugriff auf registrierte Aktionen']];
  const shellFeedback = new Map();
  const optionList = (values, selected) => values.map(([id, label]) =>
    `<option value="${id}" ${id === selected ? 'selected' : ''}>${label}</option>`).join('');

  const moodExamples = {
    quiet: ['Ruhiger Betrieb', 'Zorec blinzelt, zwinkert und neigt sich leicht.'],
    sleepy: ['Schläfrig', 'Bei anhaltender Ruhe döst Zorec ein.'],
    warning: ['Warnung', 'Eine Störung ist offen.'],
    critical: ['Kritische Lage', 'Mehrere unabhängige Störungen erfordern Aufmerksamkeit.'],
    working: ['Arbeit läuft', 'Eine Ausführung oder Nachprüfung läuft.'],
    approval: ['Freigabe offen', 'Zorec wartet auf eine Entscheidung.'],
    maintenance: ['Wartung', 'Im gewählten Bereich läuft eine Wartung.'],
    recovered: ['Wiederhergestellt', 'Eine Nachprüfung hat die Wiederherstellung bestätigt.'],
    offline: ['Offline', 'Ein Ziel ist offline.'],
    embarrassed: ['Eigener Fehler erkannt', 'Zorec bekommt rote Wangen, wenn er einen eigenen Fehler erkennt.'],
  };
  let previewMood = 'quiet';

  function previewMascot(mood) {
    const gesture = mood === 'embarrassed' ? 'embarrassed' : 'neutral';
    return window.opstendMascot.render(gesture, { mood, idle: true });
  }

  function moodPreview() {
    const choices = Object.entries(moodExamples).map(([id, [label]]) => [id, label]);
    return `<section class="panel manage-scope-detail" id="zorec-gestures" aria-labelledby="zorec-gestures-title">
      <div class="manage-panel-heading"><div><h2 id="zorec-gestures-title">Gesten ausprobieren</h2><p>Demo-Vorschau</p></div></div>
      <div class="manage-form">
        <label for="zorec-mood-preview">Reaktion</label>
        <select id="zorec-mood-preview">${optionList(choices, previewMood)}</select>
        <div class="service-tools zorec-preview-example">
          <div data-zorec-preview-mark>${previewMascot(previewMood)}</div>
          <p id="zorec-preview-status" role="status">${moodExamples[previewMood][1]}</p>
        </div>
      </div>
    </section>`;
  }

  function optionalShellControl(shell, field, label, enabled) {
    const id = `zorec-${shell}-${field}`;
    return `<div class="zorec-shell-option">
      <label for="${id}"><input type="checkbox" id="${id}" name="${field}" ${enabled ? 'checked' : ''}> ${label}</label>
      <small class="zorec-shell-warning" data-shell-warning="${field}">${enabled ? 'Abweichung vom Standard' : 'Standard aus'}</small>
    </div>`;
  }

  function shellScope(shell, field, label, levels, selected, note) {
    const id = `zorec-${shell}-${field}`;
    const [standard] = levels[0];
    return `<label for="${id}">${label}</label>
      <select id="${id}" name="${field}" data-shell-default="${standard}" aria-describedby="${id}-note">${optionList(levels, selected)}</select>
      <p id="${id}-note" class="zorec-scope-warning">${note} · <span data-shell-scope-warning>${selected === standard ? 'Standard aus' : 'Abweichung vom Standard'}</span></p>`;
  }

  function editEffectiveText(edit) {
    if (!edit.enabled) return 'Wirksam · deaktiviert. Recherche und Automation gelten bei aktivem Edit-Modus.';
    const access = writeLevels.find(([id]) => id === edit.access)?.[1];
    return `Wirksam · ${access} · Internet ${edit.internet ? 'an' : 'aus'} · Automation ${edit.automation ? 'an' : 'aus'}`;
  }

  function refreshEffectiveShells() {
    const report = document.getElementById('zorec-report-effective');
    const edit = document.getElementById('zorec-edit-effective');
    if (!report || !edit) return;
    const policyApi = window.opstendZorecPolicy;
    report.textContent = `Wirksam · ${reportLevels[policyApi.effectiveReportData()]} (begrenzt durch Admin Lesen)`;
    edit.textContent = editEffectiveText(policyApi.get()['admin-edit']);
  }

  function shellCard(id, heading, description, fields, extra = '') {
    return `<form class="panel manage-form zorec-shell-card" data-zorec-shell-form="${id}" aria-labelledby="zorec-${id}-title">
      <div class="manage-panel-heading">
        <div><h3 id="zorec-${id}-title">${heading}</h3><p>${description}</p></div>
      </div>
      ${fields}
      <div class="service-tools">
        <button class="button" type="submit">Profil speichern</button>
        ${extra}
      </div>
      <p role="status" data-shell-result>${shellFeedback.has(id) ? 'Profil im Browser gespeichert.' : ''}</p>
    </form>`;
  }

  function chatHistorySettings() {
    const chats = window.opstendZorecChats;
    const { t } = window.opstendLocale;
    return `<section class="panel manage-scope-detail" aria-labelledby="zorec-chat-settings-title">
      <div class="manage-panel-heading"><div><h2 id="zorec-chat-settings-title">${t('Chatverlauf', 'Chat history')}</h2>
        <p>${t('Der Browser behält diese Anzahl früherer Chats zusätzlich zum aktuellen Chat.', 'The browser keeps this number of previous chats in addition to the current chat.')}</p>
      </div></div>
      <form id="zorec-chat-retention-form" class="manage-form">
        <label for="zorec-chat-limit">${t('Frühere Chats behalten', 'Previous chats to keep')}</label>
        <input id="zorec-chat-limit" name="limit" type="number" required min="0" max="${chats.maxLimit}" step="1" value="${chats.limit}">
        <button class="button" type="submit">${t('Aufbewahrung speichern', 'Save retention')}</button>
        <p role="status" data-chat-retention-result></p>
      </form>
    </section>`;
  }

  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (form.id !== 'zorec-chat-retention-form') return;
    event.preventDefault();
    if (!form.reportValidity()) return;
    const chats = window.opstendZorecChats;
    const { t } = window.opstendLocale;
    chats.setLimit(form.elements.namedItem('limit').valueAsNumber);
    form.querySelector('[data-chat-retention-result]').textContent = chats.storageError
      ? t('Die Aufbewahrung konnte im Browser nicht gespeichert werden.', 'This browser could not save the retention setting.')
      : t('Aufbewahrung gespeichert.', 'Retention saved.');
  });

  function aiSettings(state) {
    const policy = window.opstendZorecPolicy.get();
    const read = policy['admin-read'];
    const edit = policy['admin-edit'];
    const report = policy.report;
    const effectiveReport = reportLevels[window.opstendZorecPolicy.effectiveReportData()];
    return `<div class="zorec-settings">
      <section class="panel manage-scope-detail">
        <div class="manage-panel-heading"><div><h2>Zorec und Modellanbieter</h2><p>Serverseitige Verbindung für freie Chatfragen</p></div></div>
        <form id="demo-ai-form" class="manage-form">
          <p id="demo-ai-connection">${state.escape(window.opstendDemoModel.label())}</p>
          <p>Für den Chat ausgewählt · <strong id="demo-ai-selected">${state.escape(demoAiSelection())}</strong></p>
          <label for="demo-ai-provider">Modellanbieter</label>
          <select id="demo-ai-provider" name="provider">${optionList(demoAiProviders, views.demoAiProvider())}</select>
          <label for="demo-ai-model">Chat-Modell</label>
          <select id="demo-ai-model" name="model">${optionList(demoAiModelOptions().map(([id, label]) => [state.escape(id), state.escape(label)]), state.escape(views.demoAiModel()))}</select>
          <div class="service-tools">
            <button class="button" id="demo-ai-discover" type="button" aria-describedby="demo-ai-discovery" ${demoAiChecking ? 'disabled' : ''}>Modelle abrufen</button>
            <button class="button" id="demo-ai-test" type="button" aria-describedby="demo-ai-probe" ${demoAiTesting ? 'disabled' : ''}>Modell testen</button>
            <button class="button primary" type="submit">Chat-Einstellungen speichern</button>
          </div>
          <p id="demo-ai-discovery" role="status">${state.escape(demoAiDiscovery)}</p>
          <p id="demo-ai-probe" role="status">${state.escape(demoAiProbe)}</p>
          <p id="demo-ai-result" role="status">Automatisch verwendet bei freien Chatfragen das verbundene Modell.</p>
          <details><summary>Verwaltete KI-Konfiguration</summary>
            <p>Automatische Modellwahl und weitere Vergleichsquellen gehören zur verwalteten KI-Konfiguration von OpsTend.</p>
          </details>
        </form>
      </section>
      ${chatHistorySettings()}
      ${modelComparisonPanel()}
      ${moodPreview()}
      <section class="zorec-shell-settings" aria-labelledby="zorec-shell-title">
        <header class="manage-panel-heading"><div>
          <h2 id="zorec-shell-title">Zorec-Shells und Werkzeugfreigaben</h2>
          <p>Die Demo speichert die Freigaben im Browser. Der Tool-Dienst verwendet Zugangsdaten über Keystore-Referenzen.</p>
        </div><button type="button" class="text-button" data-settings-tab="api">System-API öffnen</button></header>
        <div class="zorec-shell-grid">
          ${shellCard('admin-read', 'Admin Lesen', 'Standard für Admin-Chat, API-Chat und Leseaufgaben.',
            shellScope('admin-read', 'data', 'Leseumfang', readLevels, read.data, 'Erweiterter Leseumfang') +
            optionalShellControl('admin-read', 'internet', 'Internet-Recherche', read.internet))}
          ${shellCard('admin-edit', 'Admin Edit', 'Explizit wählbarer Chatmodus für Werkzeuge, Skills und Automationen.',
            optionalShellControl('admin-edit', 'enabled', 'Edit-Modus in Chat und API anbieten', edit.enabled) +
            shellScope('admin-edit', 'access', 'Schreibumfang', writeLevels, edit.access, 'Betriebsaktionen und Vollzugriff') +
            optionalShellControl('admin-edit', 'automation', 'Für KI-Automationen zulassen', edit.automation) +
            optionalShellControl('admin-edit', 'internet', 'Internet-Recherche', edit.internet) +
            `<p id="zorec-edit-effective" class="zorec-report-effective" role="status">${editEffectiveText(edit)}</p>`)}
          ${shellCard('report', 'Bericht', 'Berichte und Antworten für externe Anfragen.',
            shellScope('report', 'data', 'Freigegebene Daten', Object.entries(reportLevels), report.data, 'Zusätzliche Daten') +
            `<p id="zorec-report-effective" class="zorec-report-effective" role="status">Wirksam · ${effectiveReport} (begrenzt durch Admin Lesen)</p>` +
            optionalShellControl('report', 'internet', 'Internet-Recherche', report.internet),
            '<button class="button" type="button" data-open-zorec-report>Berichtsmodus prüfen</button>')}
        </div>
      </section>
      ${window.opstendAutonomyUI?.render(state) ?? ''}
    </div>`;
  }

  document.addEventListener('submit', (event) => {
    const id = event.target.dataset.zorecShellForm;
    if (!id) return;
    event.preventDefault();
    const fields = new FormData(event.target);
    const policyApi = window.opstendZorecPolicy;
    const policy = policyApi.get();
    const internet = fields.has('internet');
    policy[id] = id === 'admin-edit'
      ? { enabled: fields.has('enabled'), access: fields.get('access'), internet, automation: fields.has('automation') }
      : { data: fields.get('data'), internet };
    const result = policyApi.save(policy);
    if (result === true) {
      shellFeedback.set(id, true);
    } else {
      shellFeedback.delete(id);
    }
    event.target.querySelector('[data-shell-result]').textContent = result === true ? 'Profil im Browser gespeichert.' : result;
  });

  window.addEventListener('opstend:zorec-policy-changed', refreshEffectiveShells);

  document.addEventListener('change', (event) => {
    if (event.target.form?.id === 'demo-ai-compare-form') {
      const fields = event.target.form.elements;
      demoAiComparison.pair = [fields.namedItem('first').value, fields.namedItem('second').value];
      demoAiComparison.message = '';
      refreshDemoAiComparison();
      return;
    }
    if (event.target.id === 'zorec-mood-preview') {
      const mood = event.target.value;
      if (!Object.hasOwn(moodExamples, mood)) return;
      const preview = event.target.closest('#zorec-gestures');
      previewMood = mood;
      preview.querySelector('[data-zorec-preview-mark]').innerHTML = previewMascot(mood);
      preview.querySelector('#zorec-preview-status').textContent = moodExamples[mood][1];
      return;
    }
    const form = event.target.closest('[data-zorec-shell-form]');
    if (!form) return;
    const warning = form.querySelector(`[data-shell-warning="${event.target.name}"]`);
    if (warning) warning.textContent = event.target.checked ? 'Abweichung vom Standard' : 'Standard aus';
    if (Object.hasOwn(event.target.dataset, 'shellDefault')) {
      form.querySelector('[data-shell-scope-warning]').textContent = event.target.value === event.target.dataset.shellDefault
        ? 'Standard aus' : 'Abweichung vom Standard';
    }
    shellFeedback.delete(form.dataset.zorecShellForm);
    form.querySelector('[data-shell-result]').textContent = '';
  });

  document.addEventListener('submit', (event) => {
    if (event.target.id === 'demo-ai-compare-form') {
      event.preventDefault();
      void compareDemoAiModels();
      return;
    }
    if (!['demo-access-form', 'demo-ai-form', 'demo-backup-form'].includes(event.target.id)) return;
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    if (event.target.id === 'demo-backup-form') {
      backupDraft = data;
      persistDrafts();
      event.target.querySelector('#demo-backup-result').textContent = 'Zielentwurf im Browser gespeichert.';
      return;
    }
    if (event.target.id === 'demo-ai-form') {
      const provider = demoAiProviders.some(([id]) => id === data.provider) ? data.provider : views.demoAiProvider();
      const model = demoAiModelOptions().some(([id]) => id === data.model) ? data.model : views.demoAiModel();
      aiDraft = { provider, model };
      persistDrafts();
      refreshDemoAiSettings();
      event.target.querySelector('#demo-ai-result').textContent = 'Chat-Einstellungen im Browser gespeichert.';
      return;
    }
    const result = event.target.querySelector('#demo-access-result');
    if (data.profile === 'public' && data.method !== 'oidc') {
      result.textContent = 'Für dieses Profil braucht der Entwurf OIDC und MFA.';
      return;
    }
    accessDraft = data;
    persistDrafts();
    result.textContent = `Vorschau · ${accessProfiles[data.profile]} · Sitzung ${data.ttl} Minuten · ${data.method === 'oidc' ? 'OIDC und MFA' : 'lokale Admin-Sitzung'}.`;
  });

  document.addEventListener('input', (event) => {
    if (event.target.id !== 'settings-search') return;
    const query = event.target.value.trim().toLocaleLowerCase('de');
    const rail = event.target.closest('.settings-rail');
    let count = 0;
    for (const group of rail.querySelectorAll('.settings-group')) {
      let visible = false;
      for (const button of group.querySelectorAll('button')) {
        const haystack = `${button.textContent} ${button.dataset.settingsKeywords}`.toLocaleLowerCase('de');
        button.hidden = !query.split(/\s+/).every((term) => haystack.includes(term));
        if (!button.hidden) {
          visible = true;
          count += 1;
        }
      }
      group.hidden = !visible;
    }
    rail.querySelector('.settings-empty').hidden = count > 0;
  });

  views.settings = (state) => {
    const { t } = window.opstendLocale;
    const host = state.hosts[state.host]?.name;
    const tab = settingsGroups.some(([, items]) => items.some(([id]) => id === state.settingsTab)) ? state.settingsTab : 'access';
    const menu = settingsGroups.map(([label, items, english = label]) => `<div class="settings-group"><h2>${t(label, english)}</h2>
      ${items.map(([id, title, keywords, englishTitle]) => `<button type="button" class="manage-tab" aria-current="${id === tab ? 'page' : 'false'}"
        data-settings-tab="${id}" data-settings-keywords="${title} ${englishTitle} ${keywords}">${t(title, englishTitle)}</button>`).join('')}</div>`).join('');
    return `<div class="manage-screen">
      <header class="page-intro"><div><p class="eyebrow">${host ?? t('Ganze Flotte', 'Entire fleet')}</p><h1>Configuration</h1></div></header>
      <div class="settings-layout">
      <nav class="panel settings-rail" aria-label="${t('Einstellungsbereiche', 'Settings sections')}">
        <input type="search" id="settings-search" aria-label="${t('Einstellungen oder Funktionen suchen', 'Search settings or features')}" placeholder="${t('Einstellungen suchen', 'Search settings')}">
        ${menu}<p class="settings-empty" role="status" hidden>${t('Keine passenden Einstellungen.', 'No matching settings.')}</p>
      </nav>
      <div class="settings-content">
      ${tab === 'access' ? accessSettings(state)
        : tab === 'ai' ? aiSettings(state)
        : tab === 'api' ? window.opstendApiDemo.render(state)
        : tab === 'updates' ? window.opstendSelfUpdateView.render(state)
        : tab === 'hosts' ? window.opstendHostManagement.render(state)
        : tab === 'system' ? systemSettings(state)
        : tab === 'language' ? languageSettings()
        : tab === 'policies' ? `<div class="manage-layout manage-settings-layout">${policyTable(host)}${policyScope(host)}</div>`
        : tab === 'backup' ? `<div class="manage-layout manage-settings-layout">${settingsTable(tab, host, state)}${backupSetup(state)}</div>`
        : settingsTable(tab, host, state)}
      </div></div>
    </div>`;
  };
})();
