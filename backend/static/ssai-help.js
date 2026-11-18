/* "What this could be?" for each finding on the dashboard (2026-11-15 sync).
 *
 * For each kind of finding: a one-line summary, where to start, the likely causes, how to tell which one it is, and how
 * to fix it. Commands are filled in with the finding's own port, path, address or process id, but only after checking
 * that the value is exactly a port number / a plain path / an address / a number, so text from a finding can never turn
 * into a different command. Everything is escaped again when it is shown.
 *
 * SSAIHelp.forFinding(t)  -> { title, summary, start, causes: [{ cause, tell, fix, cmds: [...] }] }
 * SSAIHelp.render(t, esc) -> HTML for the details window
 */
(function (w) {
  'use strict';

  function values(t) {
    var src = String((t && (t.source || t.url)) || '');
    // IPv6 (2026-11-18): [2001:db8::5]:22 or a bare 2001:db8::5. Only hex digits, colons and dots get into a command.
    var v6b = src.match(/^\[([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\](?::(\d{1,5}))?$/i);
    var v6 = v6b ? v6b[1] : (/^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$/i.test(src) && /[0-9a-f]/i.test(src) ? src : '');
    var port = v6 ? ((v6b && v6b[2]) || '') : ((src.match(/:(\d{1,5})(?:\/|$)/) || [])[1] || '');
    var pid = (src.match(/^process:\/\/(\d{1,9})$/) || [])[1] || '';
    var path = /^\/[A-Za-z0-9._\/-]{1,200}$/.test(src) ? src : '';
    var ip = (src.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/) || [])[1] || v6;
    var domain = /^(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$/i.test(src.replace(/^https?:\/\//i, '').split(/[\/:?#]/)[0])
      ? src.replace(/^https?:\/\//i, '').split(/[\/:?#]/)[0] : '';
    return { port: port, pid: pid, path: path, ip: ip, domain: domain };
  }

  // {port} {pid} {path} {ip} {domain}: a command using a value the finding does not have is left out
  function fill(cmd, v) {
    var missing = false;
    var out = cmd.replace(/\{(port|pid|path|ip|domain)\}/g, function (_, k) { if (!v[k]) missing = true; return v[k]; });
    return missing ? null : out;
  }

  var C = function (cause, tell, fix, cmds) { return { cause: cause, tell: tell, fix: fix, cmds: cmds || [] }; };

  var HELP = {
    'suspicious-port': {
      title: 'An unusual port is open on a device',
      summary: 'A network scan found a port that is not normally open. Usually a program or gadget doing this on purpose.',
      start: 'Find out which device and which program own the port.',
      causes: [
        C('A smart TV, printer, game console or media server', 'The device name in the Origin column is a TV, printer, NAS or similar; the port is a known service for it (8008/8009 Cast, 9100 printing, 32400 Plex).',
          'Nothing to fix if you recognise it. Use the 🔕 button to stop flagging this port.', []),
        C('A program you installed on a computer (a dev server, a remote-desktop tool)', 'On the computer, the port belongs to a program you know.',
          'Stop it or bind it to 127.0.0.1 if other devices do not need it.', ['sudo ss -tlnp | grep ":{port} "']),
        C('Something you did not install (a backdoor)', 'The owning program is unfamiliar, runs from /tmp, or was installed recently.',
          'Disconnect the device, stop the program, and check it with an antivirus scan.', ['sudo ss -tlnp | grep ":{port} "', 'sudo lsof -i :{port}'])
      ]
    },
    'unexpected-listener': {
      title: 'A program started accepting connections',
      summary: 'A new listening port appeared on this machine and stayed open.',
      start: 'See which program owns the port and whether other machines can reach it.',
      causes: [
        C('A program or update you just installed', 'The owner is a known package (a database, a web server) and the port matches its documentation.',
          'Keep it if wanted; otherwise stop it or limit it to 127.0.0.1.', ['sudo ss -tlnp | grep ":{port} "', 'systemctl list-units --type=service --state=running']),
        C('A developer tool left running', 'The owner is python, node or similar, started from a project folder.', 'Stop it when you are done.', ['sudo ss -tlnp | grep ":{port} "']),
        C('A backdoor or reverse shell waiting for its owner', 'The owner is nc, socat, a shell, or a program in /tmp or /dev/shm.',
          'Disconnect the machine from the network, kill the program, look for how it got there (logins, cron, services).',
          ['sudo ss -tlnp | grep ":{port} "', 'sudo ls -l /proc/$(sudo ss -tlnp | grep ":{port} " | grep -o "pid=[0-9]*" | head -1 | cut -d= -f2)/exe'])
      ]
    },
    'c2-beacon': {
      title: "A device may be 'phoning home'",
      summary: 'A connection went out to a port that malware and crypto-miners use to talk to their controller.',
      start: 'Find the program that made the connection.',
      causes: [
        C('A crypto-miner (ports 3333, 14444, 45700 ...)', 'The program uses a lot of CPU and its command line mentions a pool or wallet.',
          'Kill it, delete its file, and find how it starts (cron, services, ~/.bashrc).', ['sudo ss -tnp | grep ":{port}"', 'top -o %CPU']),
        C('A remote-control tool (reverse shell)', 'The program is a shell, nc, socat or an interpreter connected to an outside address.',
          'Disconnect the machine and treat it as compromised: change passwords used on it.', ['sudo ss -tnp | grep ":{port}"']),
        C('A legitimate app that happens to use that port (chat, games)', 'The program is a known app and the address belongs to its vendor.',
          'Allowlist the port if you are sure.', [])
      ]
    },
    'intel-match': {
      title: 'Contact with an address on a threat list',
      summary: 'A threat feed lists the address this device talked to as malicious.',
      start: 'Find which program talked to it and whether it still does.',
      causes: [
        C('Malware on the device contacting its controller', 'The connection repeats, and the program is unfamiliar.', 'Isolate the device, remove the program, scan it.', ['sudo ss -tnp | grep "{ip}"']),
        C('A browser visited a bad site (ad, redirect)', 'The program is a browser and it happened once.', 'Clear the browser, check its extensions, block the address.', []),
        C('A shared address (cloud hosting) also used by good sites', 'The address belongs to a large cloud provider and the listing is old.', 'Check the listing date; dismiss if it is stale.', [])
      ]
    },
    'malicious-domain': {
      title: 'A device looked up a known bad website',
      summary: 'A website name on a threat list was requested from your network.',
      start: 'Find which device asked for it (Pi-hole query log).',
      causes: [
        C('A link in an e-mail or message was clicked', 'One device, one or two lookups, at a time someone was reading mail.', 'Check that device for downloads; change any password typed on that site.', []),
        C('Malware or adware on a device', 'The same device keeps looking it up, often at regular times.', 'Scan and clean that device.', []),
        C('An ad or tracker inside a normal site', 'Lookups happen together with a well-known site.', 'Usually harmless when blocked; keep the Pi-hole block.', [])
      ]
    },
    'brute-force': {
      title: 'Repeated failed sign-ins from one address',
      summary: 'One address failed to log in many times.',
      start: 'Check whether the address is outside or inside your network.',
      causes: [
        C('An internet bot guessing passwords', 'The address is outside, and SSH is reachable from the internet.', 'Turn off password sign-in for SSH (keys only); block the address.', ['sudo grep "{ip}" /var/log/auth.log | tail -20']),
        C('Someone (or a script) with an old password', 'The address is inside your network and the user name is a real one.', 'Update the saved password on that device or script.', ['sudo grep "{ip}" /var/log/auth.log | tail -20']),
        C('A security scanner or monitor you run', 'The address is your own scanner (vulnerability scan, uptime check) and it happens on a schedule.',
          'Give it a key or exclude this host from its password checks.', [])
      ]
    },
    'distributed-brute-force': {
      title: 'Password guessing spread over many addresses',
      summary: 'Many addresses each tried a few passwords, staying under the per-address alarm.',
      start: 'Make sure password sign-in is off or every password is strong.',
      causes: [
        C('A botnet attacking SSH from the internet', 'Many outside addresses, common user names (root, admin).', 'Use keys only for SSH, or put SSH behind a VPN.', ['sudo grep -c "Failed password" /var/log/auth.log']),
        C('Someone targeting one account', 'Most attempts name the same user.', 'Lock or rename that account, use a long password and keys.', ['sudo grep "Failed password" /var/log/auth.log | awk \'{print $(NF-5)}\' | sort | uniq -c | sort -rn | head'])
      ]
    },
    'brute-force-success': {
      title: 'A sign-in worked right after many failures',
      summary: 'An address that just failed several times then logged in. The password may have been guessed.',
      start: 'Act now: assume the account is compromised until you know otherwise.',
      causes: [
        C('The attacker guessed the password', 'You did not log in at that time from that address.', 'Change the password, end its sessions, check what it did, block the address.',
          ['who', 'last -n 20', 'sudo grep "{ip}" /var/log/auth.log | tail -30']),
        C('You mistyped a few times, then got it right', 'The address is yours and the time matches.', 'Dismiss it; consider SSH keys so typos stop mattering.', [])
      ]
    },
    'ssh-login': {
      title: 'Someone signed in remotely',
      summary: 'A remote sign-in happened. Usually you or a scheduled task.',
      start: 'Check whether you recognise the address and the time.',
      causes: [
        C('You or another admin', 'The address is one of your own devices.', 'Nothing to do.', []),
        C('An automated job (backup, monitoring)', 'It happens at the same time every day from a server you own.', 'Nothing to do.', []),
        C('Someone using stolen credentials', 'Unknown address or unusual time.', 'Change that account\'s password and keys; check its activity.', ['last -n 20'])
      ]
    },
    'slow-brute-force': {
      title: 'Slow password guessing over several days',
      summary: 'One address failed to log in a few times a day for several days, staying under the 48-hour alarm.',
      start: 'Check whether the address is yours, and whether password sign-in is on.',
      causes: [
        C('A patient internet bot', 'An outside address, common user names (root, admin), at odd hours.', 'Use keys only for SSH; block the address.', ['sudo grep "{ip}" /var/log/auth.log | tail -20']),
        C('A device of yours with an old saved password', 'The same user name every time, at regular times.', 'Update the saved password on that device.', ['sudo grep "{ip}" /var/log/auth.log | tail -20'])
      ]
    },
    'sudo-failure': {
      title: 'Failed attempts to get administrator rights',
      summary: 'A wrong sudo password was typed several times, or an account that may not use sudo tried it.',
      start: 'Check who it was and whether that person was at the machine.',
      causes: [
        C('You or another admin mistyped', 'The account is yours and the time matches.', 'Nothing to do.', []),
        C('Someone using a stolen or shared account', 'You were not using the machine then, or the account should never need sudo.', 'Change that account\'s password; check what it did.',
          ['sudo grep "sudo" /var/log/auth.log | tail -30', 'last -n 20']),
        C('A script or program asking for sudo', 'It repeats on a schedule.', 'Fix the script (a sudoers rule for that one command, or no sudo at all).', ['sudo grep "sudo" /var/log/auth.log | tail -30'])
      ]
    },
    'persistence-change': {
      title: 'A start-up location changed',
      summary: 'Something that runs automatically (cron, systemd units, sudo rules, PAM, shell start-up files, login keys or ld.so.preload) was added, changed or removed.',
      start: 'Look at the file and find out whether a person or an update made it.',
      causes: [
        C('A software update or package install', 'The time matches an apt/dpkg run and the file belongs to a package.', 'Nothing to do if it looks normal.',
          ['dpkg -S {path}', 'grep " install \\| upgrade " /var/log/dpkg.log | tail -20']),
        C('You or an admin set it up', 'You added the cron job, unit, key or rule yourself.', 'Nothing to do; note it.', ['sudo ls -l {path}']),
        C('An intruder making sure they come back', 'A key, job, unit or preload entry nobody added on purpose.', 'Remove it, change passwords and keys, and find how they got in.',
          ['sudo ls -l {path}', 'sudo cat {path}', 'sudo grep "sudo:" /var/log/auth.log | tail -20'])
      ]
    },
    'file-modification': {
      title: 'An important system file changed',
      summary: 'A protected file (accounts, sudo rules, SSH settings, SSAI itself) changed.',
      start: 'Find out what changed and whether a person or an update did it.',
      causes: [
        C('A software update or package install', 'The time matches an apt/dpkg run.', 'Nothing to do if the change looks normal.', ['grep " install \\| upgrade " /var/log/dpkg.log | tail -20']),
        C('An admin edited it on purpose', 'Someone used sudo at that time.', 'Nothing to do; note it.', ['sudo grep "sudo:" /var/log/auth.log | tail -20']),
        C('An attacker added an account or a key', 'A new user, a new sudo rule or SSH setting you did not make.', 'Undo the change, change passwords, look for how they got in.', ['sudo ls -l {path}', 'sudo tail -5 {path}'])
      ]
    },
    'suspicious-process': {
      title: 'A suspicious program is running',
      summary: 'A running program looks like a miner, a reverse shell or a dropper.',
      start: 'Look at the full command line and where the program file is.',
      causes: [
        C('A crypto-miner', 'High CPU, mentions stratum, a wallet, or --donate-level.', 'Kill it, delete the file, remove how it starts.', ['ps -o pid,user,%cpu,args -p {pid}', 'sudo ls -l /proc/{pid}/exe']),
        C('A reverse shell or remote-control tool', 'The command connects a shell to an outside address (nc -e, /dev/tcp, socat exec).', 'Disconnect the machine and treat it as compromised.', ['ps -o pid,user,args -p {pid}', 'sudo ls -l /proc/{pid}/fd | head']),
        C('An admin\'s own test or tool', 'You started it on purpose.', 'Stop it when done; dismiss the finding.', [])
      ]
    },
    'disk-full': {
      title: 'A disk is almost full',
      summary: 'When the disk fills, logs stop being written, which can hide an attack.',
      start: 'Find what is using the space.',
      causes: [
        C('Logs or backups growing', '/var/log or a backup folder is large.', 'Rotate or delete old logs and backups.', ['sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -15']),
        C('Downloads, containers or models', 'Docker images or AI models are large.', 'Remove unused images and models.', ['docker system df', 'df -h']),
        C('A program writing without limit (or on purpose, to hide logs)', 'One recent file or folder grows fast.', 'Stop the program; find out why it writes so much.',
          ['sudo find / -xdev -mmin -60 -size +100M 2>/dev/null | head'])
      ]
    },
    'service-failure': {
      title: 'A background service stopped',
      summary: 'A watched service was running and then was not.',
      start: 'Read the service\'s last log lines.',
      causes: [
        C('A crash or a bad configuration', 'The log shows an error just before it stopped.', 'Fix the error and restart it.', ['systemctl status --no-pager', 'journalctl -p err -n 50 --no-pager']),
        C('A planned restart (update, reboot)', 'It came back by itself a few seconds later.', 'Nothing to do.', []),
        C('Someone stopped it to hide', 'It was stopped by a user, not by an update.', 'Restart it and check who stopped it.', ['sudo grep "systemctl" /var/log/auth.log | tail -10'])
      ]
    },
    'dns-anomaly': {
      title: 'Unusual name lookups',
      summary: 'The Pi-hole blocked far more lookups than usual.',
      start: 'Open the Pi-hole query log and sort by client.',
      causes: [
        C('A device with adware or malware', 'One client makes most of the blocked lookups.', 'Clean that device.', []),
        C('A new app or smart device that tracks a lot', 'A new TV or phone app appeared at the same time.', 'Usually harmless when blocked.', [])
      ]
    },
    'new-account': {
      title: 'A new user account appeared',
      summary: 'An account was created or given admin rights.',
      start: 'Check who created it and whether it was planned.',
      causes: [
        C('An admin or an installer created it', 'It matches a software install or an admin\'s change.', 'Nothing to do.', []),
        C('An attacker kept a way back in', 'Nobody planned it, or it was added to Administrators/sudo.', 'Disable it, change admin passwords, look for other changes.', ['net user', 'net localgroup administrators'])
      ]
    },
    'log-cleared': {
      title: 'A security log was cleared',
      summary: 'Someone erased the security event log.',
      start: 'Treat as serious unless you cleared it yourself.',
      causes: [
        C('An attacker hiding their tracks', 'Nobody on your side cleared it.', 'Isolate the PC and investigate.', ['wevtutil qe Security /c:5 /rd:true /f:text']),
        C('An admin or a cleanup tool', 'It matches maintenance you did.', 'Nothing to do.', [])
      ]
    },
    'malware-detected': {
      title: 'Antivirus found malware',
      summary: 'Microsoft Defender (or the antivirus) reported a detection.',
      start: 'Check whether it was removed or only found.',
      causes: [
        C('Removed or quarantined already', 'Defender history says Removed or Quarantined.', 'Run a full scan to be sure.', ['powershell Get-MpThreatDetection | Select -First 5']),
        C('Found but still present', 'The action failed or is pending.', 'Run a full scan, then an offline scan.', ['powershell Start-MpScan -ScanType FullScan'])
      ]
    }
  };
  HELP['malware-url'] = HELP['malicious-domain'];
  HELP['remote-login'] = HELP['ssh-login'];
  HELP['suspicious-script'] = HELP['suspicious-process'];
  HELP['admin-change'] = HELP['new-account'];

  var GENERIC = {
    title: 'What this could be',
    summary: 'There is no specific guide for this kind of finding yet.',
    start: 'Read the description, check the device in the Origin column, and look at what changed around that time.',
    causes: [
      C('Normal activity that looks unusual', 'You recognise the device and the time.', 'Dismiss it, or allowlist it if it repeats.', []),
      C('Something to investigate', 'You do not recognise it.', 'Ask the AI panel (Developer view shows the verdict) and check the device.', [])
    ]
  };

  function forFinding(t) {
    var base = HELP[String((t && (t.category || t.type)) || '').toLowerCase()] || GENERIC;
    var v = values(t);
    return {
      title: base.title, summary: base.summary, start: base.start,
      causes: base.causes.map(function (c) {
        return { cause: c.cause, tell: c.tell, fix: c.fix, cmds: c.cmds.map(function (x) { return fill(x, v); }).filter(Boolean) };
      })
    };
  }

  function render(t, esc) {
    var h = forFinding(t);
    var out = '<h3>' + esc(h.title) + '</h3><p class="idn-head">' + esc(h.summary) + '</p>'
            + '<h4>Where to start</h4><p>' + esc(h.start) + '</p><h4>Possible causes</h4>';
    h.causes.forEach(function (c, i) {
      out += '<div class="help-cause"><b>' + (i + 1) + '. ' + esc(c.cause) + '</b>'
           + '<p><i>How to tell:</i> ' + esc(c.tell) + '</p><p><i>How to fix:</i> ' + esc(c.fix) + '</p>'
           + c.cmds.map(function (x) { return '<pre class="help-cmd">' + esc(x) + '</pre>'; }).join('') + '</div>';
    });
    return out + '<p class="idn-note">Commands are suggestions to run yourself; SwarmSentinel does not run them.</p>';
  }

  w.SSAIHelp = { forFinding: forFinding, render: render, categories: function () { return Object.keys(HELP); },
                 _values: values };
})(window);
