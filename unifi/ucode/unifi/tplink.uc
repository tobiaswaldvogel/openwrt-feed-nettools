'use strict';

/*
 * unifi-inform provider for TP-Link "Web Switch" (JCI/EasySmart-style
 * management, e.g. TL-SG108PE and similar) using its data/*.json API.
 *
 * The switch has no cookie-based session: login returns a "_tid_" token
 * that must be appended as a query parameter to every subsequent
 * /data/*.json call. Unlike Netgear's SID cookie this token is kept in
 * cfg.tplink_tid exactly the same way cfg.netgear_session is kept, so the
 * switch is only logged into once (or again after a detected session
 * expiry) rather than on every poll cycle.
 *
 * Requires HTTP (not HTTPS) management enabled on the switch: Security ->
 * Access Security -> HTTP Config. This provider only speaks plain HTTP,
 * consistent with API.http_request()'s usage elsewhere in this framework.
 *
 * Port activity (speed/tx/rx) comes from portUtilization.json, which is
 * queried once per physical port every poll cycle (see tplink_utilization).
 * That means an N-port switch does N+2 HTTP calls per poll (port.json,
 * poeCfgGrid.json, then one portUtilization.json per port) - still cheap
 * JSON round-trips, and login/logout no longer happen every cycle, but
 * worth knowing if you're polling a lot of ports very frequently.
 */

import * as socket from 'socket';
import { open, popen } from 'fs';

const provider_name = 'tplink';
const UNIT_TAB = 'unit1';   /* stack unit tab; "unit1" for a standalone switch */

const LINK_STATUS  = { '0': 'down', '1': 'up' };
const POWER_STATUS = { '0': 'off', '1': 'searching', '2': 'delivering', '3': 'fault' };
const POE_CLASS = { '300': 'Class 4' };

function lookup(map, key, fallback) {
	let v = map[key];
	return (v === null) ? fallback : v;
}

function mac_for_ip(ip)
{
    // Populate the ARP cache.
    let p = popen(`/bin/ping -c 1 -W 1 ${ip}`, 'r');

    if (p)
        p.close();

    let f = open('/proc/net/arp', 'r');

    if (!f)
        return null;

    // Skip header.
    f.read('line');

    for (let line = f.read('line'); line; line = f.read('line')) {
        let fields = split(line, /\s+/);

        if (fields[0] == ip) {
            f.close();
            return fields[3];
        }
    }

    f.close();

    return null;
}

function init(API, cfg) {
	if (!cfg.switch_host) {
		err('unifi-tplink: no switch host (' + CONFIG_NAME + '.main.switch_host)\n');
		return false;
	}

	if (!cfg.switch_password) {
		err('unifi-tplink: no switch password (' + CONFIG_NAME + '.main.switch_password)\n');
		return false;
	}

	const sw_addrs = socket.addrinfo(cfg.switch_host, cfg.switch_port, {
		family: socket.AF_INET,
		protocol: socket.IPPROTO_TCP
	});

	if (!sw_addrs) {
		err('unifi-tplink: Could not resolve switch host (' + cfg.switch_host + ')\n');
		return false;
	}

	cfg.ip = sw_addrs[0].addr.address;
	if (!cfg.mac)
		cfg.mac = mac_for_ip(cfg.ip);

	if (lc(cfg.mac) == "00:00:00:00:00:00") {
		err('unifi-tplink: Could not resolve MAC address for switch\n');
		return false;
	}

	return true;
}

const JSON_HEADER = { 'Content-Type': 'application/json' };

function tplink_api_path(name, cfg) {
	return sprintf('/data/%s.json?_tid_=%s&usrLvl=%d', name, cfg.tplink_tid, cfg.tplink_usrlvl);
}

/* POST a ucode object as JSON, return the decoded reply, or null on any failure */
function tplink_post(API, cfg, path, bodyObj) {
	let response = API.http_request(cfg.ip, cfg.switch_port, 'POST', path, JSON_HEADER, sprintf('%J', bodyObj));

	if (!response || response.status_code != 200)
		return null;

	let res;
	try {
		res = json(response.body);
	} catch (e) {
		return null;
	}

	/*
	 * Only login.json uses errorcode meaningfully (0 == ok); every load
	 * call observed in a live capture returns errorcode: -1 even on a
	 * genuine success, so success itself is the only field worth trusting
	 * for those.
	 */
	if (!res || !res.success)
		return null;

	return res;
}

function tplink_login(API, cfg) {
	let res = tplink_post(API, cfg, '/data/login.json', {
		username:  cfg.switch_username,
		password:  cfg.switch_password,
		operation: 'write'
	});

	if (!res || res.errorcode != 0 || !res.data || res.data._tid_ == null) {
		warn(provider_name + ': login failed\n');
		return false;
	}

	cfg.tplink_tid    = res.data._tid_;
	cfg.tplink_usrlvl = res.data.usrLvl;

	/*
	 * PoE power budget is a static system setting, not something that
	 * changes poll-to-poll - fetch it once here rather than on every
	 * collect_data() call. Cached in cfg so it survives across polls the
	 * same way the session token does; refetched only when we log in
	 * again (e.g. after a detected session expiry), which is harmless.
	 */
	let poeSysRes = tplink_post(API, cfg, tplink_api_path('poeSysCfgGrid', cfg), {
		operation: 'load'
	});

	cfg.tplink_total_max_power = (poeSysRes && length(poeSysRes.data)) ? +poeSysRes.data[0].limit : null;

	return true;
}

/*
 * Per-port traffic/speed counters. Unlike port.json/poeCfgGrid.json this is
 * queried once per physical port (body {"port":"1/0/N"}), returning
 * {"data":{"speed":<Mbps>,"tx":<bytes>,"rx":<bytes>}}. "speed" here is the
 * switch's own resolved Mbps value - authoritative, no enum guessing needed
 * (confirmed against a live capture: a port with speedLink:3 in port.json
 * reported speed:1000 here). tx/rx are cumulative byte counters; the API
 * doesn't expose packet counts, errors, or drops per port.
 */
function tplink_utilization(API, cfg, portStr) {
	let res = tplink_post(API, cfg, tplink_api_path('portUtilization', cfg), { port: portStr });

	if (!res || !res.data)
		return null;

	return res.data;
}

function tplink_status(API, cfg) {
	let portRes = tplink_post(API, cfg, tplink_api_path('port', cfg), {
		operation: 'load',
		special:   'display',
		tab:       UNIT_TAB
	});

	if (!portRes)
		return null;

	let poeRes = tplink_post(API, cfg, tplink_api_path('poeCfgGrid', cfg), {
		operation: 'load',
		tab:       UNIT_TAB
	});

	let ports = [];

	for (let p in portRes.data) {
		let segs   = split(p.port, '/');
		let portNo = segs[length(segs) - 1];

		let poe = null;
		if (poeRes)
			for (let e in poeRes.data)
				if (e.port == portNo) {
					poe = e;
					break;
				}

		let util = tplink_utilization(API, cfg, p.port);

		push(ports, {
			port:         p.port,          /* e.g. "1/0/3"            */
			portNo:       int(portNo),
			linkStatus:   p.linkStatus,
			linkState:    lookup(LINK_STATUS, p.linkStatus, 'unknown'),
			speedLink:    p.speedLink,
			speedMax:     p.speedMax,

			speed:        util ? util.speed : 0,   /* authoritative Mbps from portUtilization.json */
			txBytes:      util ? util.tx    : 0,
			rxBytes:      util ? util.rx    : 0,

			poeEnabled:   poe ? (poe.poeStatus == 1) : null,
			poePowerW:    poe ? poe.power   : null,
			poeCurrentMA: poe ? poe.current : null,
			poeVoltageV:  poe ? poe.voltage : null,
			poePdClass:   poe ? lookup(POE_CLASS, poe.pdClass, 'unknown') : null,
			poeStatus:    poe ? lookup(POWER_STATUS, poe.powerStatus, 'unknown') : null
		});
	}

	return ports;
}

function poll_switch_ports(API, cfg) {
	if (!cfg.switch_host)
		return null;

	if (!cfg.tplink_tid) {
		API.dbg(provider_name + ': logon\n');
		if (!tplink_login(API, cfg))
			return null;
	}

	let ports = tplink_status(API, cfg);

	if (!ports) {
		/* session likely expired/invalid - one relogin retry */
		API.dbg(provider_name + ': status fetch failed, retrying login\n');
		cfg.tplink_tid = null;

		if (!tplink_login(API, cfg))
			return null;

		ports = tplink_status(API, cfg);
	}

	if (ports)
		API.dbg(`unifi-tplink: switch poll complete, ${length(ports)} ports found\n`);

	return ports;
}

function shutdown(API, cfg) {
	if (cfg.tplink_tid) {
		API.dbg(provider_name + ': logoff\n');
		tplink_post(API, cfg, tplink_api_path('logout', cfg), { operation: 'write' });
		cfg.tplink_tid = null;
	}
}

/* Maps one entry from tplink_status()'s ports[] into a UniFi port_table entry. */
function tplink_port_to_unifi(idx, p) {
	const up = p.linkState == 'up';

	return {
		port_idx:      idx,
		name:          'port' + idx,
		media:         'GE',
		up:            up,
		speed:         p.speed,   /* authoritative Mbps from portUtilization.json */
		full_duplex:   true,   /* not reliably derivable from this switch's API - see note above duplexLink was dropped */
		autoneg:       true,
		is_uplink:     false,
		tx_bytes:      p.txBytes,
		tx_errors:     0,
		tx_packets:    0,
		tx_dropped:    0,
		rx_bytes:      p.rxBytes,
		rx_packets:    0,
		rx_errors:     0,
		rx_dropped:    0,
		rx_multicast:  0,
		mac_table:     [],
		poe_caps:      p.poeStatus != null ? 2 : 0,
		poe_good:      p.poeStatus && p.poeStatus != 'off',
		poe_enable:    p.poeStatus && p.poeStatus != 'off',
		poe_mode:	   p.poeStatus == 'delivering' ? 'auto' : 'off',
		poe_power:     p.poePowerW,
		poe_current:   p.poeCurrentMA,
		poe_voltage:   p.poeVoltageV,
		poe_class:     p.poePdClass,
	};
}

function collect_data(API, cfg, data) {
	data.port_table = [];

	const raw_ports = poll_switch_ports(API, cfg);

	if (!raw_ports)
		return false;

	for (let i, p in raw_ports) {
		let port = tplink_port_to_unifi(i + 1, p);
		if (port.name == cfg.uplink_port || '' + p.portNo == cfg.uplink_port)
			port.is_uplink = true;
		push(data.port_table, port);
	}

	if (cfg.tplink_total_max_power != null)
		data.total_max_power = cfg.tplink_total_max_power;

	return true;
}

return {
	defaults: {
		model: 'USF5P',
        model_display: 'USF5P',
        hostname: 'US5P',
		switch_username: 'admin',
        switch_port: '80',
        uplink_port: '5',
	},

	init: init,
	collect_data: collect_data,
	shutdown: shutdown,
};
