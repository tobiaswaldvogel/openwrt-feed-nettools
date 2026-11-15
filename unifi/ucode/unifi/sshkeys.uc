'use strict';

/*
 * SSH keys from the controller (Settings > System > Device SSH
 * Authentication) into the local authorized_keys, for the providers that
 * emulate this device itself (openwrt, openwrt_gw). Not used by the switch
 * providers: their system_cfg belongs to a remote switch, not this box.
 *
 * The controller sends the keys in system_cfg, to an AP / switch as
 *   sshd.auth.key.N.status  = enabled
 *   sshd.auth.key.N.type    = ssh-ed25519
 *   sshd.auth.key.N.value   = AAAA...
 *   sshd.auth.key.N.comment = name
 * and to a gateway inside its JSON config tree (stored as system_cfg list
 * 'config', see edgecfg.uc) as
 *   system login user <name> authentication public-keys <comment> key=AAAA...
 *   system login user <name> authentication public-keys <comment> type=ssh-...
 *
 * Enabled per instance with `option ssh_keys '1'`. The keys are kept in a
 * marked block per instance, so locally added keys and the blocks of other
 * instances stay untouched. Disabling the option, or the controller removing
 * all keys, empties the block on the next start / setparam.
 *
 * Written to /etc/dropbear/authorized_keys when dropbear is installed and to
 * /root/.ssh/authorized_keys when OpenSSH is.
 */

import { readfile, writefile, access, mkdir, chmod } from 'fs';

function enabled(cfg) {
	return cfg.ssh_keys == '1' || cfg.ssh_keys == 'true' || cfg.ssh_keys == 1;
}

function targets() {
	let t = [];
	if (access('/usr/sbin/dropbear'))
		push(t, { dir: '/etc/dropbear', file: '/etc/dropbear/authorized_keys' });
	if (access('/usr/sbin/sshd'))
		push(t, { dir: '/root/.ssh', file: '/root/.ssh/authorized_keys' });
	return t;
}

// { type, value, comment } list from either system_cfg format, or null if
// system_cfg holds no configuration at all (not provisioned yet).
function raw_keys(systemcfg) {
	if (type(systemcfg?.config) == 'array') {
		const conf = require('unifi.edgecfg').unflatten(systemcfg.config);

		let out = [];
		for (let user, u in (conf?.system?.login?.user ?? {}))
			for (let comment, k in (u?.authentication?.['public-keys'] ?? {}))
				push(out, { type: k?.type, value: k?.key, comment });
		return out;
	}

	if (!length(systemcfg ?? {}))
		return null;

	let out = [];
	if (systemcfg['sshd.auth.key.status'] == 'disabled')
		return out;

	for (let i = 1; i < 100; i++) {
		const pfx = `sshd.auth.key.${i}.`;
		if (systemcfg[pfx + 'value'] == null)
			break;
		if (systemcfg[pfx + 'status'] != 'disabled')
			push(out, { type: systemcfg[pfx + 'type'], value: systemcfg[pfx + 'value'],
			            comment: systemcfg[pfx + 'comment'] });
	}
	return out;
}

// authorized_keys lines. Type and key are validated so that nothing from
// the controller can smuggle in key options (command=...) or extra lines.
function controller_keys(systemcfg) {
	const raw = raw_keys(systemcfg);
	if (raw == null)
		return null;

	let keys = [];
	for (let k in raw) {
		const type = k.type ?? 'ssh-rsa';
		if (!match(type, /^(ssh|ecdsa|sk)-[A-Za-z0-9@.-]+$/) || !match(k.value ?? '', /^[A-Za-z0-9+\/]+=*$/)) {
			warn('unifi: ignoring malformed controller SSH key\n');
			continue;
		}

		const comment = replace(k.comment ?? '', /[^ -~]/g, '');
		push(keys, trim(`${type} ${k.value} ${comment}`));
	}
	return keys;
}

// Replace (or append) this instance's block in the file contents.
function merge_block(old, begin, end, keys) {
	let out = [], skipping = false;
	for (let line in split(old ?? '', '\n')) {
		if (line == begin) { skipping = true; continue; }
		if (skipping) { if (line == end) skipping = false; continue; }
		push(out, line);
	}
	while (length(out) && out[-1] == '')
		pop(out);

	if (length(keys))
		push(out, begin, ...keys, end);

	return length(out) ? join('\n', out) + '\n' : '';
}

function sync(API, cfg, systemcfg) {
	let keys = [];
	if (enabled(cfg)) {
		keys = controller_keys(systemcfg);
		// not provisioned (yet): keep whatever the block holds
		if (keys == null)
			return;
	}

	const begin = `# BEGIN unifi ${cfg.instance} (managed by the UniFi controller)`;
	const end   = `# END unifi ${cfg.instance}`;

	for (let t in targets()) {
		const old = readfile(t.file);
		// nothing to add and no block of ours to remove: leave the file alone
		if (!length(keys) && index(old ?? '', begin) < 0)
			continue;

		const merged = merge_block(old, begin, end, keys);
		if (merged == (old ?? ''))
			continue;

		if (!access(t.dir)) {
			mkdir(t.dir, 0o700);
		}
		if (!writefile(t.file, merged)) {
			warn(`unifi: cannot write ${t.file}\n`);
			continue;
		}
		if (old == null)
			chmod(t.file, 0o600);

		warn(`unifi: ${length(keys)} controller SSH key(s) in ${t.file}\n`);
	}
}

return { sync };
