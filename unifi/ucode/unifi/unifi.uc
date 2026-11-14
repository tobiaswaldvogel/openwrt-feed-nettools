#!/usr/bin/ucode
'use strict';

import * as socket from 'socket';
import { readfile, open, popen } from 'fs';
import { deflate, inflate } from 'zlib';
import * as uci from 'uci';
import * as uloop from 'uloop';
import { connect } from 'ubus';
import { aes128_cbc_encrypt, aes128_cbc_decrypt, aes128_gcm_encrypt, aes128_gcm_decrypt } from 'aes';
import * as math from "math";
import * as digest from 'digest';

/*
 * IMPORTANT: chr()/ord() operate on Unicode codepoints, not raw bytes -
 * chr(n) for n >= 0x80 emits a multi-byte UTF-8 sequence instead of a
 * single byte. Any hand-rolled binary packing built on chr()/ord() will
 * silently corrupt data as soon as a byte >= 0x80 shows up (half of all
 * IV/ciphertext bytes, routinely). Use the byte-oriented `struct` module
 * for all binary packing/unpacking instead.
 */
import { pack, unpack } from 'struct';


const CONFIG_NAME = 'unifi';
const DEFAULT_KEY = 'ba86f2bbe107c7c57eb5f2690775c712'; // md5("ubnt")

/* ---------------------------------------------------------------------- */
/* globals                                                                 */
/* ---------------------------------------------------------------------- */

let provider;
let cfg = {};        // static, UCI 'main' section - see load_config()
let mgmtcfg = {};     // controller-managed, UCI 'mgmt_cfg' section (named by MAC)
let systemcfg = {};   // controller-managed, UCI 'system_cfg' section (named by MAC)
let shutdown_requested = false;

/* ---------------------------------------------------------------------- */
/* debug logging                                                          */
/* ---------------------------------------------------------------------- */

function dbg(fmt, ...args) {
	if (cfg.debug)
		print(sprintf(fmt, ...args));
}

/* ---------------------------------------------------------------------- */
/* small binary / hex helpers (ucode has no native AES/hex codec)         */
/* ---------------------------------------------------------------------- */

function hex2bin(hex) {
	let out = '';
	for (let i = 0; i < length(hex); i += 2)
		out += pack('B', int(substr(hex, i, 2), 16));
	return out;
}

function bin2hex(bin) {
	let out = '';
	for (let i = 0; i < length(bin); i++)
		out += sprintf('%02x', unpack('B', substr(bin, i, 1))[0]);
	return out;
}

function random_hex(nbytes) {
	const fh = open('/dev/urandom', 'r');
	const data = fh.read(nbytes);
	fh.close();
	return bin2hex(data);
}

function u32be(n) {
	return pack('>I', n);
}

function u16be(n) {
	return pack('>H', n);
}

function be32_at(buf, off) {
	return unpack('>I', substr(buf, off, 4))[0];
}

function be16_at(buf, off) {
	return unpack('>H', substr(buf, off, 2))[0];
}

function mac_to_bytes(mac) {
	return hex2bin(replace(mac, ':', ''));
}

function mac_table_has(table, mac) {
	for (let entry in table)
		if (entry.mac == mac)
			return true;
	return false;
}

/* ---------------------------------------------------------------------- */
/* UCI / config handling                                                  */
/* ---------------------------------------------------------------------- */

function uci_get_or_create_anonymous_section(ctx, section) {
	let name;

	ctx.foreach(CONFIG_NAME, section, function(s) {
		if (s[".anonymous"]) {
			name = s[".name"];
			return false;
		}
	});

	if (!name)
		name = ctx.add(CONFIG_NAME, section);

	return name;
}

// Derives a stable, unique UCI section name for the device-specific
// mgmt_cfg / system_cfg sections from the APs MAC, e.g.
// "mgmt_cfg_04ab18d6ef01". Prefixing with the section type keeps the
// two sections from colliding (UCI names are unique per-file, not
// per-type), and guarantees the name never starts with a digit even
// though a MAC can.
function device_section(section) {
	return section + '_' + lc(replace(cfg.mac, ':', ''));
}

function uci_get_or_create_named_section(ctx, type, name) {
	let exists = false;

	ctx.foreach(CONFIG_NAME, type, function(s) {
		if (s['.name'] == name) {
			exists = true;
			return false;
		}
	});

	if (!exists) {
		const tmp = ctx.add(CONFIG_NAME, type);
		ctx.rename(CONFIG_NAME, tmp, name);
	}
	return name;
}

function load_uci_section(section, name) {
	const ctx = uci.cursor();

	let obj;
	ctx.foreach(CONFIG_NAME, section, function(s) {
		if (s['.name'] != name)
			return;
		
		if (!obj)
			obj = {};

		for (let key, value in s) {
			if (match(key, /^\./)) // ignore internal metadata keys
				continue;
			obj[replace(key, '___', '.')] = value;
		}
	});
	return obj;
}

function setparam_section(section, obj, data) {
	const ctx = uci.cursor();
	const name = device_section(section);
	uci_get_or_create_named_section(ctx, section, name);

	for (let line in split(data, '\n')) {
		line = trim(line);
		const parts = match(line, /^([^=]+)=(.*)$/);
		if (!parts)
			continue;

		const key   = trim(parts[1]);
		const value = trim(parts[2]);

		if (obj[key] == value)
			continue;

		obj[key] = value;
		ctx.set(CONFIG_NAME, name, replace(key, '.', '___'), value);
		dbg('unifi: %s -> %s\n', key, value);

		if (key == 'authkey')
			warn('unifi: received new authkey from controller, adopting\n');
	}

	ctx.commit();
	return obj;
}


function apply_defaults(cfg, defaults) {
    for (let key, def in defaults) {
        if (!cfg[key])
            cfg[key] = def;
    }
}

function load_config(instance) {
	const ctx = uci.cursor();

	let cfg = load_uci_section('instance_cfg', instance);
	if (!cfg)
		return null;

    const defaults = {
        enabled: 1,
        debug: 0,
        unifi_host: 'unifi',
        unifi_service: '8080',
        version: '1.0',
        interval: '60',
        compression: 'zlib',
        version: '1.0',
		provider: 'openwrt',
        cfgversion: '?',
    };

	apply_defaults(cfg, defaults);

	if (cfg.debug == 'true')
		cfg.debug = 1;
	else
		cfg.debug = +cfg.debug;

    let addrs = socket.addrinfo(cfg.unifi_host, cfg.unifi_service, {
		family: socket.AF_INET,
		protocol: socket.IPPROTO_TCP
	});

    if (!cfg.inform_ip)
	    cfg.inform_ip = addrs ? addrs[0].addr.address : '192.168.1.1';
	if (!cfg.inform_port)
		cfg.inform_port = addrs ? addrs[0].addr.port : 8080;
	cfg.inform_url = `http://${cfg.inform_ip}:${cfg.inform_port}/inform`;

    return cfg;
}

function setdefault() {
	const ctx = uci.cursor();

	ctx.delete(CONFIG_NAME, device_section('mgmt_cfg'));
	mgmtcfg = {};

	ctx.delete(CONFIG_NAME, device_section('system_cfg'));
	systemcfg = {};

	ctx.commit();
}

function setcfg(name, value) {
	const ctx = uci.cursor();
	const target_section = uci_get_or_create_named_section(ctx, 'instance_cfg', cfg.instance);
	cfg[name] = value;
	ctx.set(CONFIG_NAME, target_section, replace(name, '.', '___'), value);
	ctx.commit();
}

/* ---------------------------------------------------------------------- */
/* inform packet build / parse                                            */
/* ---------------------------------------------------------------------- */

function build_inform_packet(payload_json) {
	let flags = 1; // encrypted
	let plain;

	const key_hex  = mgmtcfg.authkey ?? DEFAULT_KEY;
	const iv_hex   = random_hex(16);
	const iv_bytes = hex2bin(iv_hex);

	if (cfg.compression == 'zlib') {
		plain = deflate(payload_json);
		flags |= 2;
	} else {
		plain = payload_json;
	}

	if (mgmtcfg.use_aes_gcm != 'false') {
		flags |= 8;

		const tag_len = 16;
		const enc_len = length(plain) + tag_len;
		const hdr = 'TNBU' + u32be(0) + cfg.mac_bytes + u16be(flags) +
		            iv_bytes + u32be(1) + u32be(enc_len);

		const enc = aes128_gcm_encrypt(plain, hex2bin(key_hex), iv_bytes, hdr, tag_len);
		return hdr + enc.ciphertext + enc.tag;
	}

	const encrypted = aes128_cbc_encrypt(plain, hex2bin(key_hex), iv_bytes, true);
	return 'TNBU' + u32be(0) + cfg.mac_bytes + u16be(flags) +
	       iv_bytes + u32be(1) + u32be(length(encrypted)) + encrypted;
}

function parse_inform_response(resp) {
	if (!resp || length(resp) < 40 || substr(resp, 0, 4) != 'TNBU')
		return null;

	const flags = be16_at(resp, 14);
	const plen  = be32_at(resp, 36);
	let payload = substr(resp, 40, plen);

	if (length(payload) < plen) {
		warn(`Payload too short: Expected ${plen}, got ${length(payload)}\n`);
		return null;
	}

	try {
		if (flags & 0x1) {
			const key_hex  = mgmtcfg.authkey ?? DEFAULT_KEY;
			const iv_bytes = substr(resp, 16, 16);

			if (flags & 0x8) {
				if (plen < 16) {
					warn(`unifi: GCM payload too short for tag (${plen} bytes)\n`);
					return null;
				}

				const aad = substr(resp, 0, 40);
				const enc = substr(payload, 0, plen - 16);
				const tag = substr(payload, plen - 16, 16);
				payload = aes128_gcm_decrypt(enc, hex2bin(key_hex), iv_bytes, tag, aad);
			} else {
				payload = aes128_cbc_decrypt(payload, hex2bin(key_hex), iv_bytes, true);
			}

			if (!payload) {
				warn('unifi: failed to decrypt inform response (wrong authkey?)\n');
				return null;
			}
		}

		if (flags & 0x2)
			payload = inflate(payload);

		return json(payload);
	}
	catch (e) {
		warn(`unifi: failed to parse inform response: ${e.message}\n`);
		return null;
	}
}

/* ---------------------------------------------------------------------- */
/* generic blocking HTTP client (used for both the inform POST and the    */
/* netgear switch polling)                                                */
/* ---------------------------------------------------------------------- */

function http_request(ip, port, method, path, headers, body, timeout_ms) {
	let retval = {};
	let content_length;

    if (!timeout_ms)
        timeout_ms = 5000;

	headers = headers || {};
	if (body != null)
		headers['Content-Length'] = length(body);

	let request = `${method} ${path} HTTP/1.0\r\nHost: ${ip}:${port}\r\n`;
	for (let k, v in headers)
		request += `${k}: ${v}\r\n`;
	request += '\r\n' + (body ?? '');

	const sock = socket.connect(ip, port, { family: socket.AF_INET, socktype: socket.SOCK_STREAM }, timeout_ms);
	if (!sock) {
		dbg('unifi: connect() to %s:%d failed: %s\n', ip, port, socket.error());
		return null;
	}

	const tv = { sec: timeout_ms / 1000, usec: (timeout_ms % 1000) * 1000 };
	sock.setopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, tv);
	sock.setopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, tv);

	if (sock.send(request) === null) {
		dbg('unifi send() to %s:%d failed: %s\n', ip, port, sock.error());
		sock.close();
		return null;
	}

	let response = sock.recv();

	if (response === null) {
		dbg('unifi: recv() from %s:%d failed or timed out: %s\n', ip, port, sock.error());
		sock.close();
		return null;
	}

	let peer_closed = false;

	while (true) {
		let sections = split(response, '\r\n\r\n');
		if (length(sections) > 1) {
			let components = match(sections[0], /HTTP\/([^\s]*) ([0-9]{3})([^\r\n]*)\r\n((.|\n)*)/);
			if (components) {
				retval.version     = components[1];
				retval.status_code = components[2];
				retval.status_mesg = components[3];
				retval.headers     = components[4];
			}

			/* rejoin in case the body itself contains \r\n\r\n */
			retval.body = join('\r\n\r\n', slice(sections, 1));

			let len_match = match(retval.headers, /[Cc]ontent-[Ll]ength:[^0-9]+([0-9]+)/);
			if (len_match)
				content_length = +len_match[1];

			if (content_length) {
				/* known length: read until we have it all */
				while (content_length > length(retval.body)) {
					let chunk = sock.recv();

					if (chunk === null) {
						dbg('unifi: recv() from %s:%d failed or timed out: %s\n',
							ip, port, sock.error());
						sock.close();
						return null;
					}

					if (chunk == '') {
						dbg('unifi: %s:%d closed connection before full body received\n', ip, port);
						break;
					}

					retval.body += chunk;
				}
			}
			else {
				/*
				 * No Content-Length: HTTP/1.0 servers commonly signal end
				 * of body by closing the connection. Keep reading until
				 * that happens instead of assuming we already have it all.
				 */
				while (!peer_closed) {
					let chunk = sock.recv();

					if (chunk === null) {
						dbg('unifi: recv() from %s:%d failed or timed out: %s\n',
							ip, port, sock.error());
						sock.close();
						return null;
					}

					if (chunk == '') {
						peer_closed = true;
						break;
					}

					retval.body += chunk;
				}
			}

			break;
		}

		let chunk = sock.recv();

		if (chunk === null) {
			dbg('unifi: recv() from %s:%d failed or timed out: %s\n', ip, port, sock.error());
			sock.close();
			return null;
		}

		if (chunk == '') {
			dbg('unifi: %s:%d closed connection before headers received\n', ip, port);
			sock.close();
			return null;
		}

		response += chunk;
	}

	sock.close();
	return retval;
}

function http_post_inform(ip, port, data) {
	return http_request(ip, port, 'POST', '/inform', {
		'User-Agent': 'ESP32 HTTP Client/1.0',
		'Content-Type': 'application/x-binary',
	}, data);
}

const API = {
	dbg : dbg,
	http_request: http_request
};

/* ---------------------------------------------------------------------- */
/* inform payload                                                         */
/* ---------------------------------------------------------------------- */
function get_inform_obj() {
	let hostname = systemcfg['resolv.host.1.name'];
	if (!hostname)
		hostname = cfg.hostname;

	let data = {
		default: true,
		state: 1,
		has_poe_passthrough: false,
		inform_url: cfg.inform_url,
		inform_ip: cfg.inform_ip,
		ip: cfg.ip,
		mac: cfg.mac,
		serial: uc(replace(cfg.mac, ':', '')),
		model: cfg.model,
		model_display: cfg.model_display,
		isolated: false,
		hostname: hostname,
		time: time(),
		version: cfg.version,
	};

	provider.collect_data(API, cfg, data);

	if (!data.uptime) {
		const sysstats = API.ubus.call('system', 'info');
		data.uptime = sysstats.uptime;
	}

	if (data.port_table) {
		if (cfg.lldp) {
			for (let lldp in cfg.lldp) {
				let lldp_data = split(lldp, ' ');
				let idx = +lldp_data[1];
				let mac = lc(trim(lldp_data[0]));

				let port = filter(data.port_table, p => p.port_idx == idx)[0];
				if (port) {
					if (!port.mac_table)
						port.mac_table = [];
					if (!mac_table_has(port.mac_table, mac))
						push(port.mac_table, {
							mac: mac,
							static: false
						});
				}
			}
		}

		const uplink = filter(data.port_table, p => p.is_uplink)[0];
		if (uplink) {
			data.uplink = uplink.name;
			data.if_table = [{
				name: uplink.name,
				num_port: length(data.port_table),
				ip: cfg.ip,
				mac: cfg.mac,
				speed: uplink.speed,
				full_duplex: uplink.full_duplex,
				tx_bytes: uplink.tx_bytes,
				tx_packets: uplink.tx_packets,
				tx_errors: uplink.tx_errors,
				tx_dropped: uplink.tx_dropped,
				rx_bytes: uplink.rx_bytes,
				rx_packets: uplink.rx_packets,
				rx_errors: uplink.rx_errors,
				rx_dropped: uplink.rx_dropped,
				rx_multicast: uplink.rx_multicast,
			}];
		}
	}

	if (mgmtcfg.cfgversion)
		data.cfgversion = mgmtcfg.cfgversion;

	if (mgmtcfg.authkey) {
		data.default = false;
		data.state = 2;
	}

	return data;
}

/* ---------------------------------------------------------------------- */
/* command handling (responses from the controller)                       */
/* ---------------------------------------------------------------------- */
function apply_response(response) {
	let interval = null;

	if (!response)
		return null;

	dbg('unifi: command _type=%s\n', response._type ?? '?');

	switch (response._type) {
	case 'setparam':
		if (response.mgmt_cfg) {
			mgmtcfg = setparam_section('mgmt_cfg', mgmtcfg, response.mgmt_cfg);
			if (provider.on_mgmt_cfg)
				provider.on_mgmt_cfg(API, cfg, mgmtcfg);
		}

		if (response.system_cfg) {
			systemcfg = setparam_section('system_cfg', systemcfg, response.system_cfg);
			if (provider.on_system_cfg)
				provider.on_system_cfg(API, cfg, systemcfg);
		}

		interval = 1;
		break;

	case 'cmd':
		const func = provider['cmd.' + response.cmd];
		if (func) {
			if (func(API, response.cmd, response))
				dbg(sprintf('unifi: cmd %s successful\n', response.cmd));
			else
				warn(sprintf('unifi: cmd %s failed %s\n', response.cmd, response));
		} else
			warn(sprintf('unifi: cmd %s not implemented\n', response.cmd));

		//unifi: response { "_type": "cmd", "cmd": "power-cycle", "port": 4, "device_id": "6aa6cce2776b79025c8e1732", "time": 1789319341347, "datetime": "2026-09-13T17:09:01Z", "_id": "6aa6d8ad776b79025c8e1a35", "server_time_in_utc": "1789319360571" }
		break;

	case 'upgrade':
		setcfg('version', response.version);
		interval = 1;
		break;

	case 'setdefault':
		setdefault();
		warn('unifi: Setting default values\n');
		break;

	case 'setkey':
		if (response.key) {
			mgmtcfg.key = response.key;
			mgmtcfg.adopted = true;
			warn('unifi: received new authkey from controller, adopting\n');
		}
		break;

	case 'noop':
		/* nothing to do */
		break;

	default:
		warn(sprintf('unifi: received unhandled command _type=%s\n', response._type ?? '?'));
		interval = 1;
		break;
	}

	if (response.cfgversion)
		setcfg('cfgversion', response.cfgversion);

	if (response.interval)
		interval = response.interval;

	return interval;
}

/* ---------------------------------------------------------------------- */
/* one inform cycle                                                       */
/* ---------------------------------------------------------------------- */

function do_inform() {
	const data = get_inform_obj();
	const payload_json = sprintf('%J', data);
	dbg('unifi: request %s\n', payload_json);

	const packet = build_inform_packet(payload_json);
	if (!packet) {
		warn('unifi: failed to build inform packet, skipping cycle\n');
		return null;
	}

	const response = http_post_inform(cfg.inform_ip, cfg.inform_port, packet);
	if (!response) {
        warn('unifi: failed to send inform packet, skipping cycle\n');
        return null;
    }

    dbg('unifi: response status code %d\n', response.status_code);

	if (response.status_code == 400) {
		warn('unifi: controller returned 400 Bad Request\n');
		return null;
	}

	if (response.status_code != 200)
		return null;

	const decoded = parse_inform_response(response.body);
	dbg('unifi: response %s\n', decoded);

	return apply_response(decoded);
}

/* ---------------------------------------------------------------------- */
/* main                                                                    */
/* ---------------------------------------------------------------------- */

function request_shutdown(name) {
	warn(sprintf('unifi: received %s, shutting down\n', name));
	shutdown_requested = true;
	uloop.end();
}

function rss_kb() {
	for (let l in split(readfile('/proc/self/status'), '\n'))
		if (substr(l, 0, 6) == 'VmRSS:')
			return +match(l, /[0-9]+/)[0];
}

function main(instance, debug_override) {
	print(`unifi: starting up, instance ${instance}\n`);

	API.ubus = connect();
	cfg = load_config(instance);

	if (debug_override != null)
		cfg.debug = debug_override in [ '1', 'true', 'yes', 'on' ];

	if (!cfg) {
		warn('unifi: no configuration found, exiting\n');
		return 1;
	}

	if (!cfg.enabled) {
		warn('unifi: disabled via UCI (unifi.main.enabled=0), exiting\n');
		return 0;
	}

	provider = require('unifi.' + cfg.provider);

	if (provider.defaults) 
		apply_defaults(cfg, provider.defaults);

	if (provider.init) {
		if (!provider.init(API, cfg)) {
			warn('unifi: init for provider ' + cfg.provider + ' failed, exiting\n');
			return 1;
		}
	}

    cfg.instance = instance;
	cfg.mac_bytes = mac_to_bytes(cfg.mac);

	mgmtcfg = load_uci_section('mgmt_cfg', device_section('mgmt_cfg')) ?? {};
	if (provider.on_mgmt_cfg)
		provider.on_mgmt_cfg(API, cfg, mgmtcfg);

	systemcfg = load_uci_section('system_cfg', device_section('system_cfg')) ?? {};
	if (provider.on_system_cfg)
		provider.on_system_cfg(API, cfg, systemcfg);

	uloop.init();

	uloop.signal('SIGINT', () => request_shutdown('SIGINT'));
	uloop.signal('SIGTERM', () => request_shutdown('SIGTERM'));

	warn(sprintf('unifi: emulating %s (%s) -> %s [%s]\n',
		cfg.model, cfg.mac, cfg.inform_url,  systemcfg['resolv.host.1.name'] ?? cfg.hostname));

	const timer = uloop.timer(-1, () => uloop.end());

	while (!shutdown_requested) {
		const interval = do_inform() || cfg.interval;

		gc();

		if (cfg.debug) {
			gc('collect');
			warn(`gc_count=${gc('count')} rss=${rss_kb()}kB\n`);
		}

		if (!shutdown_requested) {
			timer.set(interval * 1000);
			uloop.run();
		}
	}

	if (provider.shutdown)
		provider.shutdown(API, cfg);

	uloop.done();
	return 0;
}

exit(main(ARGV[0] ?? '', ARGV[1]));
