/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-guest-enabled-001)
 *
 * Note on answer order: the engine re-orders every question from the case seed
 * (see shuffleCase in app.js), so the order below is only the authoring order.
 * It is deliberately varied anyway — no single-answer question puts the correct
 * option first, and no multi-select question puts the correct options in the
 * leading slots — so the source is safe to read even without the shuffle.
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-guest-enabled-001',
    title: 'The Nobody Account',
    difficulty: 'Beginner',
    seed: 109,
    caseRef: 'CASE 006',
    host: 'sec-win-04',
    host_ip: '10.0.4.13',
    log_sources: ['auth'],

    mission: {
      brief: 'Investigate workstation sec-win-04.',
      objective: 'Establish how an attacker obtained access without creating an account or using a stolen password.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      'An attacker with a foothold on a workstation enabled the normally disabled Guest account, then ' +
      'authenticated as Guest from the same external IP. The Guest account bypasses password policies and is ' +
      "a favourite persistence trick because many admins never check it.",

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin4-events.evtx']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the account trail',
        trail: 'assemble the sequence',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'Which account was used, and what was its state on this host before the hour began?',
        'What happened between the account being switched on and the logon that used it?',
        'What does that session hold that it should not — and how would it have come by it?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The order is the finding: an account switched on at 08:04, the same external address logging on as it ' +
        'two minutes later, and an administrator token handed to that session another two minutes after that. ' +
        'Nothing new was created — the attacker used a door that was already in the wall, and unlocked it.',

      /* ledger wording, so the analyst journal reads in the case's own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus account and host-baseline reference data',
        timeline:
          'Identified the pattern: a policy-disabled account switched on, then used from the same external address',
        triageContext:
          'Kept the compromised logon as context rather than evidence — it anchors the timeline without proving ' +
          'the persistence',
        board:
          'Correlated the full chain: external source → compromised account → Guest enabled → logon as Guest → ' +
          'administrator token',
        attack: 'Mapped the persistence to ATT&CK T1078.003 Valid Accounts: Local Accounts',
        attackAlso: 'Identified the supporting technique: T1098.003 Account Manipulation: Enable Account',
        host: 'Scoped the incident to host sec-win-04'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Subject', v: 'mchen', flag: '— standard account, session from 203.0.113.45' },
        { k: 'Account', v: 'Guest', flag: '— disabled by policy on every production host until 08:04:19' },
        { k: 'Token', v: 'administrator', flag: '— Guest is entitled to hold no privileges at all' },
        { k: 'Trail', v: 'mchen 08:01:22 → Guest enabled 08:04:19 → logon as Guest 08:06:33 → admin token 08:08:40' }
      ],
      trailLabel: 'REVEAL THE FULL SEQUENCE',
      journalDecode:
        'Assembled the sequence — Guest enabled at 08:04:19, logon as Guest from 203.0.113.45 at 08:06:33, ' +
        'administrator token assigned at 08:08:40',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-04 (10.0.4.13)', code: true },
          { label: 'Account used', value: 'Guest — enabled in-session, never created', code: true },
          { label: 'Enable event', value: '1 × 4722 by mchen, policy said it must stay disabled', code: true },
          { label: 'Logon', value: '1 × 4624 as Guest from 203.0.113.45, logon type 10', code: true },
          { label: 'Token', value: '1 × 4672 — administrator token issued to a Guest session', code: false },
          { label: 'TTP', value: 'Valid Accounts: Local Accounts T1078.003 — persistence', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-foothold',
        ts: '08:01:22',
        code: 4624,
        kind: 'event',
        host: 'sec-win-04',
        actor: 'mchen',
        text: 'Successful interactive logon. Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'context',
        why:
          'This is the foothold \u2014 the interactive entry point, and the reason the later records can be ' +
          'attributed to somebody at all. You need it to anchor the timeline and to know whose session did the ' +
          'rest, but one remote logon is not evidence of persistence.'
      },
      {
        id: 'ev-4722-guest-enabled',
        ts: '08:04:19',
        code: 4722,
        kind: 'event',
        host: 'sec-win-04',
        text: 'Local account enabled: Guest. Changed by: mchen. Previous state: disabled.',
        tags: 'signal',
        why:
          'Guest ships with every copy of Windows and is disabled by policy across this estate, which is why ' +
          'nothing in the account inventory changes. A standard user switching it on is not provisioning \u2014 it ' +
          'is choosing an account nobody reviews.'
      },
      {
        id: 'ev-4624-guest',
        ts: '08:06:33',
        code: 4624,
        kind: 'event',
        host: 'sec-win-04',
        actor: 'Guest',
        text: 'Successful interactive logon. Account "Guest". Source 203.0.113.45 (remote). Logon type 10.',
        tags: 'signal',
        why:
          'The account that was disabled two minutes ago just logged on interactively, from the same external ' +
          'address that opened the session. Note what is missing: no new account, no password change, no ' +
          'credential of any kind. That absence is the whole point.'
      },
      {
        id: 'ev-4672-guest',
        ts: '08:08:40',
        code: 4672,
        kind: 'event',
        host: 'sec-win-04',
        actor: 'Guest',
        text: 'Special privileges assigned to new logon. Token: elevated (administrator).',
        tags: 'signal',
        why:
          'A Guest session is entitled to no privileges at all, so an administrator token here is not routine. ' +
          'Event 4672 appears twenty times in this hour across the estate for ordinary users \u2014 it is the ' +
          'identity of the session that makes this one the finding, not the event code.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:33', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:06', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:49', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:24', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:02', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:36', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:14', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:41', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:09', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:27', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:44', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:52', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:18', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:31', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:42', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:05', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:26', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:39', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:11', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:18', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-4722-guest',
        ref: 'ALERT-01',
        severity: 'high',
        title: 'Guest account enabled',
        blurb: 'The local Guest account was enabled on sec-win-04 (Event 4722). Guest should remain disabled on all production hosts.',
        detail:
          'Security Event 4722 \u2014 "A user account was enabled". Fields of interest: TargetUserName (which ' +
          'account), SubjectUserName (who enabled it) and the timestamp. Guest is built into every copy of ' +
          'Windows and is deliberately left disabled by policy here, so an account-state change of any kind is ' +
          'a deviation \u2014 and this one was made by a user session, not by a management agent.',
        hint: 'Ask: which account, by whom, and does this host\u2019s baseline say that account should be off?'
      },
      {
        id: 'al-4624-guest',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Successful logon as Guest account',
        blurb: 'The Guest account successfully authenticated to sec-win-04 (Event 4624) shortly after being enabled.',
        detail:
          'Security Event 4624 \u2014 "An account was successfully logged on". The source address is the same ' +
          'external address that opened the session three minutes earlier, and the logon type is 10, an ' +
          'interactive remote logon. What makes this more than a curiosity is what did not happen: no account ' +
          'was created, no password was set, and no credential was presented that was not already on the host.',
        hint: 'Ask: what credential did this logon use, and where did it come from?'
      },
      {
        id: 'al-4672-guest',
        ref: 'ALERT-03',
        severity: 'high',
        title: 'Privileges assigned to Guest logon',
        blurb: 'Special privileges were assigned to the Guest logon session on sec-win-04 (Event 4672). Guest should have no privileges.',
        detail:
          'Security Event 4672 \u2014 "Special privileges assigned to new logon". This event appears constantly ' +
          'on the estate, which is exactly why the account name in the session matters more than the code: a ' +
          'Guest session is entitled to no privileges whatsoever, so an elevated token here cannot be explained ' +
          'by a user running something as administrator.',
        hint: 'Ask: which account is in the session, and is it supposed to be able to hold an administrator token?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account information — mchen',
        blurb: 'Directory record for the account whose session enabled and used the Guest account.',
        detail:
          'mchen \u2014 M. Chen, Payroll Analyst, 31 months in post. Group membership: Domain Users, ' +
          'Payroll-Read. Not a member of local Administrators and not in any group with account-management ' +
          'rights, so there is no approved workflow in which this user changes local account state. Interactive ' +
          'logon history for 90 days: 10.0.4.x and VPN concentrator addresses only.',
        hint: 'Ask: is there any legitimate reason for this account to change the state of another account?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic and account state for the estate during the same window.',
        detail:
          'Guest is disabled on all 1,240 production workstations and servers, re-applied by group policy every ' +
          '90 minutes; no drift was recorded anywhere before 08:00 today. In this hour, 5 baseline users ' +
          'generated 20 logon, logoff and privilege events across FIN-WS-14, HR-LT-03, ENG-WS-02, OPS-WS-09, ' +
          'FIN-LT-11 and SALES-LT-11. No other host enabled any account, and no session anywhere authenticated ' +
          'as Guest.',
        hint: 'Ask: is this the only host in the estate where Guest is doing anything at all?'
      }
    ],

    alerts: [
      { name: 'Guest account enabled', severity: 'high' },
      { name: 'Successful logon as Guest account', severity: 'high' },
      { name: 'Privileges assigned to Guest logon', severity: 'high' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:01:22', label: 'Logon', detail: "1 successful logon for 'mchen' on sec-win-04 from 203.0.113.45 (compromised session)", net: null },
      { t: 'T+3', ts: '08:04:19', label: 'Account', detail: "user_account_enabled (4722): Guest account enabled on sec-win-04 by 'mchen'", net: null },
      { t: 'T+5', ts: '08:06:33', label: 'Logon', detail: 'successful_logon (4624) for "Guest" on sec-win-04 from 203.0.113.45', net: null },
      { t: 'T+7', ts: '08:08:40', label: 'Privilege', detail: 'special_privileges_assigned (4672) for "Guest" on sec-win-04 — administrator token', net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'A shared workstation where a user signed in to the Guest profile to finish a print job' },
        { id: 'b', label: 'An approved help-desk task that enabled Guest temporarily to install a printer driver' },
        { id: 'c', label: 'A failed logon, an account reset and a retry \u2014 somebody could not get back into their own account' },
        { id: 'd', label: 'A compromised session enabling an account policy had disabled, then logging on as it from the same external address and holding administrator rights' }
      ],
      correct: ['d'],
      xp: 10,
      explain:
        'The order and the absences are what rule out the alternatives. An account that policy keeps disabled is ' +
        'switched on inside a session that came from outside, and then used from that same address \u2014 with no ' +
        'new account, no new password and no help-desk change record anywhere in the hour. A printer task does ' +
        'not come from 203.0.113.45, and a forgotten password produces failed logons, not an elevated Guest ' +
        'session.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-src', label: '203.0.113.45', sub: 'external source', x: 8, y: 8 },
      { id: 'n-user', label: 'mchen', sub: 'compromised account', x: 8, y: 62 },
      { id: 'n-guest', label: 'Guest', sub: 'disabled by policy', x: 40, y: 36 },
      { id: 'n-logon', label: 'interactive session', sub: 'logon type 10, external', x: 40, y: 82 },
      { id: 'n-admin', label: 'administrator token', sub: 'special privileges (4672)', x: 72, y: 8 }
    ],
    boardLinks: [
      { from: 'n-src', to: 'n-user', label: 'authenticates as', correct: true },
      { from: 'n-user', to: 'n-guest', label: 'enables', correct: true },
      { from: 'n-src', to: 'n-guest', label: 'authenticates as', correct: true },
      { from: 'n-guest', to: 'n-logon', label: 'starts', correct: true },
      { from: 'n-logon', to: 'n-admin', label: 'elevates to', correct: true },
      { from: 'n-guest', to: 'n-src', label: 'downloads from', correct: false },
      { from: 'n-admin', to: 'n-user', label: 'created by', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify enabling the local Guest account and then logging on as it?',
        options: [
          { id: 'a', label: 'Initial Access \u2014 this is how the attacker reached the workstation' },
          { id: 'b', label: 'Impact \u2014 the Guest session destroyed something on the host' },
          { id: 'c', label: 'Persistence \u2014 a standing way back in that uses an account nobody audits, without creating a credential' },
          { id: 'd', label: 'Credential Access \u2014 the Guest session read stored passwords off the host' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The attacker was already inside; this is about staying inside. Nothing had to be created or cracked: ' +
          'the account was switched on and used again whenever the attacker chooses, which is persistence. It is ' +
          'worth naming why Guest specifically \u2014 it exists on every Windows host, it bypasses password ' +
          'policy, and it is never in an account review, so the attack produces no new entry for anyone to spot.'
      },
      {
        id: 'q-ps',
        prompt: 'Why reuse the built-in Guest account rather than create a local account of your own?',
        options: [
          { id: 'a', label: 'It is the only Windows account that can log on without a password at all' },
          { id: 'b', label: 'Windows deletes it automatically after 30 days of disuse' },
          { id: 'c', label: 'It is excluded from password length and complexity policy by default' },
          { id: 'd', label: 'It already exists everywhere and is never audited \u2014 so the attacker needs no new credential and nothing changes in the account inventory' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'Creating a local administrator leaves a name in the account list, a new object for a password audit to ' +
          'catch and something for a baseline scan to flag. Guest leaves none of those traces, because the ' +
          'account was always there and is supposed to be switched off rather than watched. Options A and C are ' +
          'the comfortable half-truths: Guest is disabled precisely because it is not meant to be usable, and ' +
          'the point is the absence of a trace, not a shortcut around a password policy.'
      }
    ],

    decodedCommand: {
      encoded: 'mchen 08:01:22 \u2192 Guest enabled 4722 08:04:19 \u2192 logon as Guest 4624 08:06:33 \u2192 admin token 4672 08:08:40',
      decoded: 'local Guest account enabled (4722) \u2192 interactive logon as Guest from 203.0.113.45 (4624) \u2192 administrator token assigned to that session (4672)',
      note:
        'The three event IDs read as one action with three steps: switch the account on, walk in through it, keep ' +
        'the keys. What makes this case different from a new-account intrusion is the missing fourth record \u2014 ' +
        'there is no 4720, no password change and no new account anywhere in the hour, because the attacker ' +
        'needed none of them.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains how the attacker keeps access without creating anything?',
        options: [
          { id: 'a', label: 'Create or Modify System Process: Windows Service', meta: 'T1543.003 \u00b7 Persistence' },
          { id: 'b', label: 'Scheduled Task/Job', meta: 'T1053.005 \u00b7 Execution / Persistence' },
          { id: 'c', label: 'Valid Accounts: Local Accounts', meta: 'T1078.003 \u00b7 Persistence / Privilege Escalation' },
          { id: 'd', label: 'Exploitation of Remote Services', meta: 'T1210 \u00b7 Initial Access' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The defining artifact is a built-in local account that was already on the host being switched on and ' +
          'used \u2014 no account created, no credential obtained. That is Valid Accounts: Local Accounts, ' +
          'T1078.003, and it is persistence precisely because there is nothing new to inventory. Creating a ' +
          'service or a scheduled task would both have left an object behind, which is what this attacker is ' +
          'avoiding.'
      },
      alsoPresent: {
        prompt: 'One further technique is genuinely present. Select it.',
        options: [
          { id: 'a', label: 'Account Manipulation: Additional Local or Domain Groups', meta: 'T1098.007 \u00b7 Privilege Escalation' },
          { id: 'b', label: 'Account Manipulation: Enable Account', meta: 'T1098.003 \u00b7 Persistence / Privilege Escalation' },
          { id: 'c', label: 'Indicator Removal: Clear Windows Event Logs', meta: 'T1070.001 \u00b7 Defense Evasion' },
          { id: 'd', label: 'Access Token Manipulation: Token Impersonation/Theft', meta: 'T1134 \u00b7 Privilege Escalation' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'The switch-on is its own technique: enabling an account that policy keeps disabled is Account ' +
          'Manipulation \u2014 Enable Account, T1098.003 \u2014 and it is the step that makes the Valid Accounts ' +
          'logon possible at all. Nothing in the stream shows a group change (option A), a token being stolen or ' +
          'impersonated (option D), or any log clearing (option C): the records are all intact, which is why ' +
          'this case is solvable.'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: '203.0.113.45', role: 'indicator' },
        { id: 'i2', label: '4722 enabling the Guest account', role: 'indicator' },
        { id: 'i3', label: 'sec-win-04', role: 'context' },
        { id: 'i4', label: 'mchen', role: 'context' },
        { id: 'i5', label: 'Event 4672', role: 'context' },
        { id: 'i6', label: 'a policy-disabled account switched on and then used', role: 'behaviour' },
        { id: 'i7', label: 'interactive logon as an account nobody audits', role: 'behaviour' },
        { id: 'i8', label: 'administrator token issued to a Guest session', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you would act on today: the external source 203.0.113.45 (block it and ' +
        'look for other hosts) and the literal 4722 enabling the Guest account, which is a precise hunt across ' +
        'the estate rather than a description of one host. The behaviours \u2014 a policy-disabled account ' +
        'switched on and then used, an interactive logon as an account that should never log on, and an ' +
        'administrator token issued to a Guest session \u2014 are the detections worth engineering, and the last ' +
        'of them is the one that will not fire on anything legitimate. sec-win-04, mchen and Event 4672 are ' +
        'context: they scope the incident and tell you where to pivot, but they are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host is compromised?',
        options: [
          { id: 'a', label: 'FIN-LT-11' },
          { id: 'b', label: 'HR-LT-03' },
          { id: 'c', label: 'sec-win-04' },
          { id: 'd', label: '10.0.4.20' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'All four relevant records belong to sec-win-04: the external logon, the enablement of Guest, the ' +
          'Guest logon and the privileged session. The other hosts were busy in the same hour and produced ' +
          'nothing, and 10.0.4.20 is an address, not a host name.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'A shared workstation where a user signed in to the Guest profile to clear a print queue.' },
          { id: 'b', label: 'An approved help-desk task that temporarily enabled Guest so a printer driver could be installed.' },
          { id: 'c', label: 'An account lockout after repeated failed logons, resolved by a support engineer.' },
          { id: 'd', label: 'An attacker in a compromised session for mchen enabled the policy-disabled local Guest account, logged on as Guest from 203.0.113.45, and received an administrator token \u2014 leaving an unaudited account that needs no new password to be used again.' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'The assessment has to name the mechanism, the account, the address and the consequence: a built-in ' +
          'local account enabled in-session, used from outside, and holding administrator rights. Drop the last ' +
          'clause \u2014 that it can be used again with no new credential \u2014 and you have described an ' +
          'intrusion rather than the persistence mechanism that makes it survive.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'Guest accounts are normal on shared workstations and are enabled by default' },
          { id: 'b', label: 'Policy keeps Guest disabled on every production host, and this session switched it on' },
          { id: 'c', label: 'The Guest logon came from 203.0.113.45 \u2014 the same external address that opened the session minutes earlier' },
          { id: 'd', label: 'Users sometimes sign in as Guest when their own account is locked' },
          { id: 'e', label: 'Guest was issued an administrator token, which policy says it must never hold' },
          { id: 'f', label: 'No account was created and no password changed, so nothing appears in the account inventory' }
        ],
        correct: ['b', 'c', 'e', 'f'],
        xp: 10,
        explain:
          'Each of the four is anchored to a record or to a fact you were given: a policy deviation, an address ' +
          'that recurs across two sessions, an entitlement that cannot be justified, and the total absence of ' +
          'new-account evidence. The other two are generalisations that would excuse every intrusion of this ' +
          'kind \u2014 Guest is disabled by default on this estate, and an account lockout produces failed ' +
          'logons rather than a privileged Guest session.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The account-state record, the logon, the host baseline and the account record for mchen all agree, ' +
          'and they agree in one order: enable, log on, elevate \u2014 from the same address throughout. What we ' +
          'cannot say from this hour is what was done inside the privileged session, and that limits the impact ' +
          'assessment, not the conclusion that the host carries an attacker-controlled account.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Reimage every workstation in the payroll department as a precaution' },
          { id: 'b', label: 'Disable the Guest account again and verify that policy actually re-applies to it' },
          { id: 'c', label: 'Reset mchen\u2019s credentials and revoke active sessions and cached credentials' },
          { id: 'd', label: 'Block all outbound port 445 across the estate' },
          { id: 'e', label: 'Hunt the estate for 4722 events and for any session that authenticates as Guest' },
          { id: 'f', label: 'Remove the Guest account from the base image so it can never be enabled' }
        ],
        correct: ['b', 'c', 'e'],
        xp: 10,
        explain:
          'Close the door and confirm it stays closed: disable Guest again, and check that policy is what keeps ' +
          'it disabled rather than the attacker\u2019s change being quietly reverted. The account that opened the ' +
          'session is still the attacker\u2019s, so reset it and kill its sessions. And a single guest session on ' +
          'one host is a reason to sweep every 4722 and every Guest logon across the estate. The other three ' +
          'measure the wrong thing: option F breaks software that legitimately expects the account to exist, ' +
          'and options A and D are indiscriminate.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'mchen is a member of Domain Users only', key: false },
        { id: 'r2', label: 'Event 4722: the Guest account was enabled by mchen at 08:04:19, three minutes into the session', key: true },
        { id: 'r3', label: 'Four other users were active on the estate during the same hour', key: false },
        { id: 'r4', label: 'Event 4624: Guest logged on interactively from 203.0.113.45, the address that opened the session', key: true },
        { id: 'r5', label: 'Event 4672 is routine and appears on every administrator logon', key: false },
        { id: 'r6', label: 'Event 4672: an administrator token was issued to a Guest session, which policy says must hold none', key: true },
        { id: 'r7', label: 'The workstation had pending definition updates that morning', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'No single record proves an attacker: administrators do enable accounts, guest sessions do sometimes ' +
        'appear on shared machines, and 4672 is one of the most frequent events on the estate. What makes this ' +
        'defensible is the chain \u2014 a policy-disabled account switched on by a standard user, then used from ' +
        'the same external address, then issued an administrator token \u2014 three records, one address, one ' +
        'order. Options about account rights, estate busyness, routine 4672s or update schedules describe the ' +
        'background, not the incident.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      guest_account_enabled_events: 1,
      successful_logons_for_guest: 1,
      special_privileges_for_guest: 1,
      target_host: 'sec-win-04',
      attacker_ip: '203.0.113.45',
      event_ids_present: [4624, 4672, 4722]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the persistence and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start with Event 4722 at 08:04:19 and ask what a standard user was doing switching Guest on.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Ignore how common Event 4672 is on this estate, and look at whose session it was granted to. That is the difference here.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'Three steps: a door is unlocked, the attacker walks through it, and the keys are handed over. Which event is which?' },
      explain: { label: 'Explain', mult: 0.5, text: 'A session for mchen from 203.0.113.45 enabled the local Guest account at 08:04:19 (4722), which group policy keeps disabled on every production host. Two minutes later Guest logged on interactively from the same address (4624), and two minutes after that its session was issued an administrator token (4672). That is Valid Accounts: Local Accounts, T1078.003 — persistence — with Account Manipulation: Enable Account, T1098.003, behind it. No account was created and no password changed, which is exactly why it survives an account inventory: the attacker needed no credential of their own.' }
    }
  });
})();