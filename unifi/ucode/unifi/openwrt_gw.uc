'use strict';

/*
 * UniFi inform provider: gateway (USG/UXG-style).
 *
 * Drop-in sibling of the AP provider (unifi.openwrt). The main daemon loads
 * this when the instance is configured with `option provider 'gateway'`, via
 * require('unifi.gateway'); install this file as unifi/gateway.uc on the ucode
 * module path.
 *
 * Physical-port model (matches a real UGW3): the controller expects exactly
 * three wired interfaces named eth0, eth1, eth2, with eth0 as WAN. A real
 * router has far more L3 interfaces than that (every VLAN and WireGuard peer
 * is one), so reporting them all floods if_table/network_table with entries a
 * USG would never send. Instead we resolve the box's *physical* ports and map
 * them onto eth0/1/2:
 *
 *   eth0 = the physical port backing the OpenWrt interface named 'wan'
 *   eth1 = first remaining physical port (link-up ports preferred)
 *   eth2 = second remaining physical port, if any
 *
 * if_table and port_table then contain only those three; network_table carries
 * every configured network — the native LAN on each port plus each VLAN, with
 * its VLAN id and (where configured) its DHCP pool. Tunnels (WireGuard, etc.)
 * are excluded, because their L3 device isn't one of the physical ports.
 *
 * The eth0/1/2 -> real-devname mapping is resolved once in init() and held for
 * the session, so a port's identity doesn't flap between informs if a cable is
 * pulled. Restarting the daemon re-detects.
 *
 * IMPORTANT interaction with the base get_inform_obj(): when `data.port_table`
 * is present AND some port has is_uplink==true, the base collapses uplink +
 * if_table down to a single entry derived from that port. Right for an AP,
 * wrong for a gateway. So this provider builds if_table/uplink itself and
 * leaves is_uplink==false on every port_table entry, making that base block a
 * no-op. The gateway's uplink is conveyed via data.uplink + the purpose:"wan"
 * network instead.
 */

import { readfile, popen, opendir, access } from 'fs';
import * as math from 'math';
import * as uci from 'uci';

/* ------------------------------------------------------------------ */
/* module-level state (persists across inform cycles in one process)   */
/* ------------------------------------------------------------------ */

let prev_cpu;   // { total, idle } from the previous /proc/stat sample
let gw_cfg;     // cfg reference, so cmd.* handlers (which aren't passed cfg) can reach it

// speedtest run state, carried across inform cycles
let st_state = { status: 0, started: 0, result: null };   // status: 0 idle, 1 running, 2 done
const ST_RESULT = '/tmp/unifi_speedtest.json';
const ST_TMP    = ST_RESULT + '.tmp';

/* ------------------------------------------------------------------ */
/* ip helpers (self-contained; not shared with the AP provider)        */
/* ------------------------------------------------------------------ */

function ipv4_to_int(ip) {
	let p = split(ip, '.');
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

function ip_in_subnet(target, net_ip, masklen) {
	let mask = masklen == 0 ? 0 : (0xffffffff << (32 - masklen));
	return (ipv4_to_int(target) & mask) == (ipv4_to_int(net_ip) & mask);
}

function masklen_to_netmask(len) {
	if (len <= 0)
		return '0.0.0.0';
	let m = (0xffffffff << (32 - len)) & 0xffffffff;
	return sprintf('%d.%d.%d.%d', (m >> 24) & 0xff, (m >> 16) & 0xff, (m >> 8) & 0xff, m & 0xff);
}

// 802.1q/802.1ad devices declared in /etc/config/network, which can have
// any name (e.g. "eth2-lan" on eth2 with vid 3), so neither the parent
// nor the VLAN id can be derived from the name. name -> { parent, vid }
let vlan_devs = {};

function load_vlan_devs() {
	vlan_devs = {};
	try {
		uci.cursor().foreach('network', 'device', (s) => {
			if (s.name && s.ifname && s.vid && (s.type == '8021q' || s.type == '8021ad'))
				vlan_devs[s.name] = { parent: s.ifname, vid: +s.vid };
		});
	} catch (e) {}
}

// The single lower device of a stacked netdev not known to netifd, e.g.
// an ipvlan/macvlan created by a script ("ipvlan-man@eth2-man"), from
// the kernel's /sys/class/net/<dev>/lower_<name> links. Bridges are left
// alone (their ports are lower devices too, handled via bridge-members).
function single_lower(dev) {
	if (!dev || access(`/sys/class/net/${dev}/bridge`))
		return null;

	const dir = opendir(`/sys/class/net/${dev}`);
	if (!dir)
		return null;

	let lower, n = 0, e;
	while ((e = dir.read()) != null) {
		if (substr(e, 0, 6) == 'lower_') {
			lower = substr(e, 6);
			n++;
		}
	}
	dir.close();

	return (n == 1) ? lower : null;
}

// One step down a VLAN/stacked device: named VLAN devices from the network
// config first, then the kernel's lower device. null for a base device.
function parent_dev(dev) {
	return vlan_devs[dev]?.parent ?? single_lower(dev);
}

// VLAN sub-interface "eth1.10", a named VLAN device ("eth2-lan") or a
// device stacked on top of one ("ipvlan-man" on "eth2-man") -> physical
// "eth1" / "eth2". Plain names are left untouched.
function strip_vlan(dev) {
	for (let depth = 0; depth < 4; depth++) {
		const p = parent_dev(dev);
		if (!p)
			break;
		dev = p;
	}

	return split(dev, '.')[0];
}

// VLAN id of an L3 device: named VLAN devices from the network config
// ("eth2-lan" -> 3, also through devices stacked on them), otherwise from
// the name ("eth1.10" / "br-lan.20" -> 10 / 20). 0 means untagged (native).
function vlan_id(dev) {
	for (let depth = 0; depth < 4 && dev; depth++) {
		if (vlan_devs[dev])
			return vlan_devs[dev].vid;

		const m = match(dev, /\.([0-9]+)$/);
		if (m)
			return +m[1];

		dev = single_lower(dev);
	}

	return 0;
}

/* ------------------------------------------------------------------ */
/* host stats                                                          */
/* ------------------------------------------------------------------ */

// CPU % from /proc/stat deltas. First inform after start returns 0 (no
// previous sample); every cycle after is a real busy-% over the interval.
function read_cpu_usage() {
	const stat = readfile('/proc/stat');
	if (!stat)
		return 0;

	const fields = filter(split(split(stat, '\n')[0], ' '), x => length(x) > 0);
	if (fields[0] != 'cpu')
		return 0;

	let total = 0, idle = 0;
	for (let i = 1; i < length(fields); i++) {
		const v = +fields[i];
		total += v;
		if (i == 4 || i == 5)   // idle + iowait
			idle += v;
	}

	let usage = 0;
	if (prev_cpu) {
		const dt = total - prev_cpu.total;
		const di = idle - prev_cpu.idle;
		if (dt > 0)
			usage = math.round(1000.0 * (dt - di) / dt) / 10;
	}
	prev_cpu = { total, idle };

	return usage;
}

// WAN RTT in ms via one ping, or null. 1s deadline so it can't stall a cycle.
function ping_latency(host) {
	if (!host)
		return null;
	const p = popen(sprintf('ping -c 1 -W 1 %s 2>/dev/null', host));
	if (!p)
		return null;
	const out = p.read('all');
	p.close();
	const m = match(out, /time=([0-9]+(\.[0-9]+)?)/);
	return m ? +m[1] : null;
}

// Rough active-client count on a subnet from the kernel ARP cache.
function count_clients(net_ip, masklen) {
	const arp = readfile('/proc/net/arp');
	if (!arp)
		return 0;
	let n = 0;
	const lines = split(arp, '\n');
	for (let i = 1; i < length(lines); i++) {
		const f = filter(split(lines[i], ' '), x => length(x) > 0);
		if (length(f) < 4)
			continue;
		if (f[2] == '0x0')      // incomplete ARP entry
			continue;
		if (ip_in_subnet(f[0], net_ip, masklen))
			n++;
	}
	return n;
}

/* ------------------------------------------------------------------ */
/* speedtest                                                           */
/*                                                                     */
/* Runs on demand when the controller sends {"_type":"cmd",            */
/* "cmd":"speedtest"} and reports the cached result in every inform as */
/* data['speedtest-status']. The test is launched detached (to a temp  */
/* file, renamed into place when complete) so it never blocks the      */
/* inform loop; each cycle polls for the finished file. Supports Ookla */
/* `speedtest -f json` and `librespeed-cli --json`, autodetected and   */
/* overridable with `option speedtest_bin` / `option speedtest_server`.*/
/* Disable entirely with `option speedtest '0'`.                       */
/* ------------------------------------------------------------------ */

function speedtest_enabled(cfg) {
	return !(cfg.speedtest == '0' || cfg.speedtest == 'false' || cfg.speedtest == 0);
}

function find_bin(name) {
	for (let dir in ['/usr/sbin', '/usr/bin', '/sbin', '/bin'])
		if (access(`${dir}/${name}`))
			return `${dir}/${name}`;
	const p = popen(`command -v ${name} 2>/dev/null`);
	if (p) {
		const o = trim(p.read('all'));
		p.close();
		if (length(o))
			return o;
	}
	return null;
}

// Returns { cmd, kind } for the chosen client, or null if none installed.
function speedtest_client(cfg) {
	let bin, kind;

	if (cfg.speedtest_bin) {
		bin  = (index(cfg.speedtest_bin, '/') >= 0) ? cfg.speedtest_bin : find_bin(cfg.speedtest_bin);
		kind = match(cfg.speedtest_bin, /librespeed/) ? 'librespeed' : 'ookla';
	}
	if (!bin) { bin = find_bin('speedtest');      if (bin) kind = 'ookla'; }
	if (!bin) { bin = find_bin('librespeed-cli'); if (bin) kind = 'librespeed'; }
	if (!bin)
		return null;

	const server = cfg.speedtest_server;
	if (kind == 'ookla')
		return { cmd: `${bin} -f json --accept-license --accept-gdpr${server ? ' -s ' + server : ''}`, kind };
	return { cmd: `${bin} --json${server ? ' --server ' + server : ''}`, kind };
}

// Normalises Ookla and librespeed-cli JSON into one shape. Ookla reports
// bandwidth in bytes/s (-> *8/1e6 for Mbps); librespeed already reports Mbps.
function parse_speedtest(raw) {
	let j;
	try { j = json(raw); } catch (e) { return null; }
	if (!j)
		return null;

	let dl, ul, ping, srv = {};

	if (type(j.download) == 'object') {            // Ookla
		dl   = (j.download.bandwidth ?? 0) * 8 / 1000000.0;
		ul   = (j.upload?.bandwidth ?? 0) * 8 / 1000000.0;
		ping = j.ping?.latency ?? 0;
		srv  = { name: j.server?.name, city: j.server?.location,
		         country: j.server?.country, cc: j.server?.country_code };
	} else {                                       // librespeed-cli
		dl   = +(j.download ?? 0);
		ul   = +(j.upload ?? 0);
		ping = +(j.ping ?? 0);
		srv  = { name: j.server?.name };
	}

	return {
		xput_download: math.round(dl * 100) / 100,
		xput_upload:   math.round(ul * 100) / 100,
		latency:       math.round(ping * 10) / 10,
		server: { name: srv.name, city: srv.city, country: srv.country, cc: srv.cc },
	};
}

// Each inform while a test is in flight: pick up the finished result file,
// or give up (keeping any previous result) after a generous timeout.
function poll_speedtest() {
	if (st_state.status != 1)
		return;

	const raw = readfile(ST_RESULT);
	if (raw) {
		const r = parse_speedtest(raw);
		if (r) {
			r.rundate = time();
			r.runtime = st_state.started ? (time() - st_state.started) : 0;
			st_state.result = r;
			st_state.status = 2;
			return;
		}
	}

	if (st_state.started && (time() - st_state.started) > 180)
		st_state.status = 0;
}

function speedtest_status_obj() {
	let s = st_state.status;
	if (st_state.result && s == 0)
		s = 2;                  // show the last result while idle

	let o = {
		source_interface: 'eth0',   // the test runs over the WAN (eth0)
		status_download: s, status_upload: s,
		status_ping: s, status_summary: s,
	};

	const r = st_state.result;
	if (r) {
		o.xput_download = r.xput_download;
		o.xput_upload   = r.xput_upload;
		o.latency       = r.latency;
		o.rundate       = r.rundate ?? 0;
		o.runtime       = r.runtime ?? 0;
		o.server        = r.server;
	}
	return o;
}

// cmd.speedtest: launch a detached run. `&` backgrounds it inside the shell
// popen() spawns, which then exits at once, so this returns immediately and
// the result is picked up by poll_speedtest() on a later inform.
function cmd_speedtest(API, cmd, response) {
	if (!speedtest_enabled(gw_cfg)) {
		API.dbg('unifi/gateway: speedtest disabled via UCI\n');
		return false;
	}
	if (st_state.status == 1) {
		API.dbg('unifi/gateway: speedtest already running\n');
		return true;
	}

	const client = speedtest_client(gw_cfg);
	if (!client) {
		warn('unifi/gateway: no speedtest client found (install speedtest or librespeed-cli)\n');
		return false;
	}

	st_state.status  = 1;
	st_state.started = time();

	const sh = sprintf('rm -f %s %s; (%s > %s 2>/dev/null && mv %s %s) &',
		ST_RESULT, ST_TMP, client.cmd, ST_TMP, ST_TMP, ST_RESULT);
	const p = popen(sh);
	if (p) p.close();

	API.dbg('unifi/gateway: speedtest launched (%s)\n', client.kind);
	return true;
}

// The controller's locate/blink. Nothing to blink on an emulated box; just
// ack it so the daemon doesn't log it as unimplemented.
function cmd_locate(API, cmd, response) {
	return true;
}

/* ------------------------------------------------------------------ */
/* per-netdev stats, shaped like the AP provider's get_port_obj()      */
/* ------------------------------------------------------------------ */

function dev_stats(all_devices, name) {
	const d = all_devices[name];
	if (!d)
		return {};

	const st = d.statistics ?? {};
	let speed = 0, full_duplex = false;
	if (d.speed) {
		full_duplex = (substr(d.speed, -1) == 'F');
		speed = int(d.speed);
	}

	return {
		up: d.carrier ?? false,
		carrier: d.carrier ?? false,
		autoneg: d.autoneg ?? true,
		speed: speed,
		full_duplex: full_duplex,
		mac: d.macaddr,
		rx_bytes: st.rx_bytes ?? 0,
		rx_packets: st.rx_packets ?? 0,
		rx_errors: st.rx_errors ?? 0,
		rx_dropped: st.rx_dropped ?? 0,
		rx_multicast: st.multicast ?? 0,
		tx_bytes: st.tx_bytes ?? 0,
		tx_packets: st.tx_packets ?? 0,
		tx_errors: st.tx_errors ?? 0,
		tx_dropped: st.tx_dropped ?? 0,
	};
}

/* ------------------------------------------------------------------ */
/* interface / physical-port discovery                                 */
/* ------------------------------------------------------------------ */

function find_iface(dump, name) {
	for (let iface in dump.interface)
		if (iface.interface == name)
			return iface;
	return null;
}

function iface_ipv4(iface) {
	const a = iface?.['ipv4-address']?.[0];
	if (!a)
		return null;
	return { ip: a.address, masklen: a.mask, netmask: masklen_to_netmask(a.mask) };
}

// Physical devices underlying an L3 device: expands a bridge to its member
// ports, strips VLAN tags, and passes a plain NIC through unchanged.
function base_phys_devs(dev, all_devices) {
	if (!dev)
		return [];

	// Strip any VLAN tag first so "br-lan.10" resolves via the "br-lan"
	// bridge (-> its member ports), not as a device literally named
	// "br-lan". A plain "eth1.10" reduces to "eth1".
	const underlying = strip_vlan(dev);
	const bm = all_devices[underlying]?.['bridge-members'] ?? all_devices[dev]?.['bridge-members'];
	if (bm) {
		let out = [], seen = {};
		for (let m in bm) {
			const p = strip_vlan(m);
			if (!seen[p]) { seen[p] = true; push(out, p); }
		}
		return out;
	}
	return [ underlying ];
}

// Enumerate real physical netdevs from sysfs. Two passes, same reasoning as
// the AP provider's sysfs fallback:
//   1) DSA switch ports carry phys_switch_id and are unambiguously physical.
//   2) Standalone NICs: have a 'device' symlink, aren't wireless (no
//      phy80211), aren't VLAN/bridge/etc (no DEVTYPE in uevent), and aren't
//      the DSA conduit feeding the switch (no upper_<dsaport> link).
// This returns DSA slave ports (lan1.., wan) on switch SoCs and discrete
// eth0/eth1/eth2 on multi-NIC boards (x86 etc), which is what we want.
function detect_phys_ports() {
	let dsa = [], all = [];
	const dir = opendir('/sys/class/net');
	if (dir) {
		let e;
		while ((e = dir.read())) {
			if (e == '.' || e == '..')
				continue;
			push(all, e);
			if (readfile(`/sys/class/net/${e}/phys_switch_id`))
				push(dsa, e);
		}
		dir.close();
	}

	let ports = [ ...dsa ];
	for (let c in all) {
		if (c in ports)
			continue;
		if (access(`/sys/class/net/${c}/phy80211`))       // wireless
			continue;

		const uevent = readfile(`/sys/class/net/${c}/uevent`);
		let has_devtype = false;
		if (uevent)
			for (let line in split(uevent, '\n'))
				if (substr(line, 0, 8) == 'DEVTYPE=') { has_devtype = true; break; }
		if (has_devtype)                                   // vlan/bridge/bond/...
			continue;

		if (!access(`/sys/class/net/${c}/device`))         // not real hardware
			continue;

		let conduit = false;
		for (let p in dsa)
			if (access(`/sys/class/net/${c}/upper_${p}`)) { conduit = true; break; }
		if (conduit)                                       // DSA master, not a jack
			continue;

		push(ports, c);
	}

	sort(ports);
	return ports;
}

/* ------------------------------------------------------------------ */
/* init: resolve eth0/1/2 -> real device mapping (held for session).   */
/* Runs before cfg.mac_bytes is computed in main(), so setting cfg.mac  */
/* here makes the packet-header MAC match the payload.                  */
/* ------------------------------------------------------------------ */

function init(API, cfg) {
	gw_cfg = cfg;
	load_vlan_devs();

	const dump = API.ubus.call('network.interface', 'dump');
	const all_devices = API.ubus.call('network.device', 'status');

	if (!dump?.interface) {
		warn('unifi/gateway: network.interface dump unavailable\n');
		return false;
	}

	// WAN: prefer the interface literally named 'wan'; fall back to whatever
	// carries the default route.
	let wan_iface = find_iface(dump, cfg.wan_iface ?? 'wan');
	if (!wan_iface) {
		for (let iface in dump.interface)
			for (let route in (iface.route ?? []))
				if (route.target == '0.0.0.0' && route.mask == 0 && iface.up) {
					wan_iface = iface;
					break;
				}
	}
	if (!wan_iface) {
		warn('unifi/gateway: no WAN interface found\n');
		return false;
	}
	cfg.wan_iface = wan_iface.interface;

	// Physical port backing WAN. Use the underlying device (not l3_device,
	// which may be pppoe-wan), reduced to its physical base.
	const wan_under = wan_iface.device ?? wan_iface.l3_device;
	const wan_phys  = base_phys_devs(wan_under, all_devices)[0];

	// Full physical-port set. Allow an explicit override via UCI
	// (`list phys_port 'eth0'` ...) for odd boards; otherwise autodetect.
	let phys = cfg.phys_port;
	if (type(phys) == 'string')
		phys = [ phys ];
	if (!phys || !length(phys))
		phys = detect_phys_ports();

	// Make sure the WAN port is in the set (detection can miss it on some
	// pppoe/exotic setups), and that we know its link state for ordering.
	if (wan_phys && !(wan_phys in phys))
		push(phys, wan_phys);

	// Non-WAN ports, connected ones first, then by name — so eth1 is the
	// "first connected physical port" you asked for.
	let rest = filter(phys, p => p != wan_phys);
	sort(rest, (a, b) => {
		const ca = all_devices[a]?.carrier ? 1 : 0;
		const cb = all_devices[b]?.carrier ? 1 : 0;
		if (ca != cb) return cb - ca;          // carrier up first
		return (a < b) ? -1 : (a > b) ? 1 : 0; // then name
	});

	// Assemble eth0/1/2. A UGW3 has exactly three ports, so cap at two
	// non-WAN ports; extra physical ports (eth3+) are ignored.
	cfg.gw_ports = [];
	if (wan_phys)
		push(cfg.gw_ports, { eth: 'eth0', dev: wan_phys, role: 'wan' });
	if (length(rest) > 0)
		push(cfg.gw_ports, { eth: 'eth1', dev: rest[0], role: 'lan' });
	if (length(rest) > 1)
		push(cfg.gw_ports, { eth: 'eth2', dev: rest[1], role: 'lan' });

	if (length(rest) > 2)
		API.dbg('unifi/gateway: %d physical ports found, only eth0/1/2 reported (UGW3 has 3)\n',
			length(phys));

	// Device identity MAC = WAN port MAC (matches real USG), with fallbacks.
	if (!cfg.mac) {
		if (wan_phys && all_devices[wan_phys]?.macaddr)
			cfg.mac = all_devices[wan_phys].macaddr;
		else if (wan_phys)
			cfg.mac = trim(readfile('/sys/class/net/' + wan_phys + '/address'));
	}
	if (!cfg.mac) {
		warn('unifi/gateway: could not determine device MAC\n');
		return false;
	}

	for (let p in cfg.gw_ports)
		API.dbg('unifi/gateway: %s -> %s (%s)\n', p.eth, p.dev, p.role);

	// Carry the last speedtest result across restarts so the controller's
	// WAN card isn't blank until the next run.
	if (speedtest_enabled(cfg)) {
		const raw = readfile(ST_RESULT);
		if (raw) {
			const r = parse_speedtest(raw);
			if (r) { st_state.result = r; st_state.status = 2; }
		}
	}

	return true;
}

/* ------------------------------------------------------------------ */
/* per-inform payload                                                  */
/* ------------------------------------------------------------------ */

// Build a map: physical dev -> primary untagged IPv4 of the network riding
// on it. Untagged interfaces win over tagged (VLAN) ones, so eth1 reports
// the native LAN address rather than a random VLAN. WireGuard/tun and other
// non-physical interfaces fall out naturally: their base device isn't one of
// our ports, so they're never assigned.
function build_phys_ip_map(dump, all_devices, gw_ports, wan_iface_name) {
	let want = {};
	for (let p in gw_ports)
		want[p.dev] = true;

	// the port's address: the 'lan' network if it rides on that port,
	// otherwise the first one found
	let ifaces = [ ...dump.interface ];
	sort(ifaces, (a, b) => (b.interface == 'lan') - (a.interface == 'lan'));

	let map = {};
	for (let tagged_pass in [ false, true ]) {   // untagged first, then tagged
		for (let iface in ifaces) {
			if (iface.interface == wan_iface_name)
				continue;
			const a = iface_ipv4(iface);
			if (!a)
				continue;

			const dev = iface.l3_device ?? iface.device;
			const is_tagged = vlan_id(dev) != 0;
			if (is_tagged != tagged_pass)
				continue;

			for (let phys in base_phys_devs(dev, all_devices)) {
				if (want[phys] && !map[phys])
					map[phys] = { ...a, name: iface.interface };
			}
		}
	}
	return map;
}

/* ------------------------------------------------------------------ */
/* network_table: every configured network + VLAN that rides on the    */
/* physical ports. if_table/port_table stay physical (eth0/1/2); VLANs  */
/* appear here with a `vlan` id, which is how a real USG represents them.*/
/* ------------------------------------------------------------------ */

function int_to_ip(n) {
	return sprintf('%d.%d.%d.%d', (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}

function leasetime_secs(s) {
	const m = match(s ?? '', /^([0-9]+)\s*([smhd])?$/);
	if (!m)
		return 86400;
	const n = +m[1];
	switch (m[2]) {
		case 's': return n;
		case 'm': return n * 60;
		case 'h': return n * 3600;
		case 'd': return n * 86400;
		default:  return n;        // bare number = seconds
	}
}

// interface-name -> dnsmasq DHCP config, read from UCI. Best-effort: if the
// read fails, networks simply come back without pool details.
function dhcp_map() {
	let m = {};
	try {
		const ctx = uci.cursor();
		ctx.foreach('dhcp', 'dhcp', (s) => {
			if (!s.interface)
				return;
			m[s.interface] = {
				ignore: (s.ignore == '1' || s.ignore == 1),
				start: s.start ? +s.start : null,
				limit: s.limit ? +s.limit : null,
				leasetime: s.leasetime,
			};
		});
	} catch (e) {}
	return m;
}

function build_network_table(cfg, dump, all_devices, wan) {
	let networks = [];

	let eth_of = {};               // physical dev -> eth name
	for (let p in cfg.gw_ports)
		eth_of[p.dev] = p.eth;

	const dhcp = dhcp_map();

	/* WAN */
	if (wan.ip) {
		let n = {
			name: 'wan',
			ifname: 'eth0',
			purpose: 'wan',
			up: true,
			enable: true,
			ip: wan.ip.ip,
			netmask: wan.ip.netmask,
			ip_subnet: sprintf('%s/%d', wan.ip.ip, wan.ip.masklen),
			num_sta: 0,
			gateways: wan.gw ? [ wan.gw ] : [],
			nameservers: wan.dns ?? [],
		};
		const wvid = vlan_id(wan.iface?.l3_device ?? wan.iface?.device);
		if (wvid) { n.vlan = wvid; n.vlan_enabled = true; }
		push(networks, n);
	}

	/* LAN + every VLAN that rides on a physical port */
	for (let iface in dump.interface) {
		if (iface.interface == wan.name || iface.interface == 'loopback')
			continue;

		const a = iface_ipv4(iface);
		if (!a)
			continue;

		const l3 = iface.l3_device ?? iface.device;

		// Which physical port does this network sit on? First member wins
		// for a bridge. If none of its base devices is one of our ports,
		// it's a tunnel/other interface — skip it.
		let eth, pdev;
		for (let d in base_phys_devs(l3, all_devices)) {
			if (eth_of[d]) { eth = eth_of[d]; pdev = d; break; }
		}
		if (!eth)
			continue;

		const vid = vlan_id(l3);
		// Prefer the VLAN netdev's own counters if it exists as a device;
		// otherwise fall back to the parent port's.
		const st = dev_stats(all_devices, all_devices[l3] ? l3 : pdev);
		const is_guest = match(iface.interface, /guest/i) ? true : false;

		let n = {
			name: iface.interface,
			ifname: vid ? sprintf('%s.%d', eth, vid) : eth,
			purpose: is_guest ? 'guest' : 'corporate',
			is_guest: is_guest,
			up: st.up,
			enable: true,
			mac: st.mac ?? cfg.mac,
			ip: a.ip,
			netmask: a.netmask,
			ip_subnet: sprintf('%s/%d', a.ip, a.masklen),
			num_sta: count_clients(a.ip, a.masklen),
			rx_bytes: st.rx_bytes, tx_bytes: st.tx_bytes,
			rx_packets: st.rx_packets, tx_packets: st.tx_packets,
		};

		if (vid) {
			n.vlan = vid;
			n.vlan_enabled = true;
		}

		// DHCP pool for this network, if dnsmasq serves it. start/limit are
		// offsets from the subnet base, same as /etc/config/dhcp.
		const d = dhcp[iface.interface];
		if (d && !d.ignore && d.start != null && d.limit != null) {
			const maskint = a.masklen == 0 ? 0 : ((0xffffffff << (32 - a.masklen)) & 0xffffffff);
			const base = ipv4_to_int(a.ip) & maskint;
			n.dhcpd_enabled = true;
			n.dhcpd_start = int_to_ip(base + d.start);
			n.dhcpd_stop  = int_to_ip(base + d.start + d.limit - 1);
			n.dhcpd_leasetime = leasetime_secs(d.leasetime);
		} else if (d && d.ignore) {
			n.dhcpd_enabled = false;
		}

		push(networks, n);
	}

	return networks;
}

/* ------------------------------------------------------------------ */
/* LLDP: put the neighbour switch's MAC on the port facing it, so the   */
/* controller draws the gateway<->switch link in the topology. Same     */
/* mechanism the AP provider uses for AP<->switch (mac_table), plus a    */
/* top-level lldp_table, which the topology view keys on directly.      */
/* ------------------------------------------------------------------ */

function mac_table_has(table, mac) {
	for (let e in (table ?? []))
		if (lc(e.mac) == lc(mac))
			return true;
	return false;
}

// Current lldpd neighbours as [{ ifname, macs[] }]. ifname is the local
// netdev lldpd heard the neighbour on; macs are its chassis-id (first) and
// port-id where those are MACs. json0 always emits arrays, so the structure
// can be walked uniformly regardless of neighbour count.
function get_lldp_neighbors() {
	const p = popen('lldpcli -f json0 show neighbors 2>/dev/null');
	if (!p)
		return null;
	const raw = p.read('all');
	p.close();
	if (!raw || !length(trim(raw)))
		return null;

	let data;
	try { data = json(raw); } catch (e) { return null; }

	let neighbors = [];
	for (let lldp in (data?.lldp ?? [])) {
		for (let iface in (lldp?.interface ?? [])) {
			let macs = [], seen = {};
			for (let section in [ iface.chassis, iface.port ]) {
				for (let s in (section ?? [])) {
					for (let id in (s?.id ?? [])) {
						if (id.type != 'mac' || !id.value)
							continue;
						const mac = lc(id.value);
						if (!seen[mac]) { seen[mac] = true; push(macs, mac); }
					}
				}
			}
			if (length(macs))
				push(neighbors, { ifname: iface.name, macs });
		}
	}
	return length(neighbors) ? neighbors : null;
}

// Attach each neighbour's MAC(s) to the port_table entry for the port it was
// heard on, and return a lldp_table. A neighbour on a bridged LAN (lldpd
// reports the bridge) is attributed to the first member port we recognise.
function apply_lldp(API, cfg, port_table, all_devices) {
	const neighbors = get_lldp_neighbors();
	if (!neighbors)
		return [];

	let eth_of = {};
	for (let p in cfg.gw_ports)
		eth_of[p.dev] = p.eth;

	let lldp_table = [];

	for (let n in neighbors) {
		let eth;
		for (let d in base_phys_devs(n.ifname, all_devices)) {
			if (eth_of[d]) { eth = eth_of[d]; break; }
		}
		if (!eth)
			continue;

		const port = filter(port_table, p => p.name == eth)[0];
		if (!port)
			continue;

		port.mac_table = port.mac_table ?? [];
		for (let mac in n.macs)
			if (!mac_table_has(port.mac_table, mac))
				push(port.mac_table, { mac: mac, static: false });
		port.mac_table_count = length(port.mac_table);

		push(lldp_table, {
			chassis_id: n.macs[0],          // neighbour's primary MAC
			local_port_idx: port.port_idx,
			local_port_name: eth,
			is_wired: true,
		});

		API.dbg('unifi/gateway: LLDP neighbour %s on %s\n', n.macs[0], eth);
	}

	return lldp_table;
}

function collect_data(API, cfg, data) {
	load_vlan_devs();

	const sysinfo = API.ubus.call('system', 'info');
	const all_devices = API.ubus.call('network.device', 'status');
	const dump = API.ubus.call('network.interface', 'dump');

	/* ---- system stats (controller reads both shapes) ---- */
	const mem_total = sysinfo.memory.total;
	const mem_free  = sysinfo.memory.free + sysinfo.memory.cached + sysinfo.memory.buffered;
	const mem_used  = mem_total - mem_free;
	const mem_usage = math.round(1000.0 * mem_used / mem_total) / 10;

	data.uptime = sysinfo.uptime;
	data['system-stats'] = {
		cpu: sprintf('%.1f', read_cpu_usage()),
		mem: sprintf('%.1f', mem_usage),
		uptime: sprintf('%d', sysinfo.uptime),
	};
	data.sys_stats = {
		loadavg_1:  sysinfo.load[0] / 65536.0,
		loadavg_5:  sysinfo.load[1] / 65536.0,
		loadavg_15: sysinfo.load[2] / 65536.0,
		mem_total:  mem_total,
		mem_used:   mem_used,
		mem_buffer: sysinfo.memory.buffered,
	};

	// Capability bitfields are model/firmware specific; only emit what's
	// supplied via UCI (capture from `mca-dump` on a real USG/UXG).
	for (let k in ['fw_caps', 'fw2_caps', 'hw_caps', 'wifi_caps'])
		if (cfg[k])
			data[k] = +cfg[k];

	/* ---- resolve live per-port IPs ---- */
	const wan_iface = find_iface(dump, cfg.wan_iface);
	const wan_ip    = iface_ipv4(wan_iface);
	const wan_dns   = wan_iface?.['dns-server'] ?? [];
	let wan_gw;
	for (let route in (wan_iface?.route ?? []))
		if (route.target == '0.0.0.0' && route.mask == 0)
			wan_gw = route.nexthop;
	const latency = ping_latency(wan_gw ?? wan_dns[0] ?? '1.1.1.1');

	const ip_map = build_phys_ip_map(dump, all_devices, cfg.gw_ports, cfg.wan_iface);

	// Returns the {ip,netmask,masklen,name} for a port: WAN address for
	// eth0, the port's primary untagged network otherwise.
	function port_ip(p) {
		if (p.role == 'wan')
			return wan_ip;
		return ip_map[p.dev];
	}

	// Top-level ip: the WAN address, like a real gateway.
	if (wan_ip)
		data.ip = wan_ip.ip;

	data.config_network_wan = {
		type: (wan_iface?.proto == 'static') ? 'static'
		    : (wan_iface?.proto == 'pppoe')  ? 'pppoe'
		    : 'dhcp',
	};

	/* ---- if_table + port_table + network_table, eth0/1/2 only ---- */
	let if_table = [];
	let port_table = [];
	let idx = 1;

	for (let p in cfg.gw_ports) {
		const st = dev_stats(all_devices, p.dev);
		const a  = port_ip(p);

		// if_table entry (named eth0/1/2, stats from the real device).
		let ife = {
			name: p.eth,
			mac: st.mac ?? cfg.mac,
			up: st.up,
			enable: true,
			speed: st.speed,
			full_duplex: st.full_duplex,
			rx_bytes: st.rx_bytes, rx_packets: st.rx_packets,
			rx_errors: st.rx_errors, rx_dropped: st.rx_dropped,
			rx_multicast: st.rx_multicast,
			tx_bytes: st.tx_bytes, tx_packets: st.tx_packets,
			tx_errors: st.tx_errors, tx_dropped: st.tx_dropped,
		};
		if (a) {
			ife.ip = a.ip;
			ife.netmask = a.netmask;
		}
		if (p.role == 'wan') {
			ife.latency = latency ?? 0;
			ife.drops = 0;
			ife.gateways = wan_gw ? [ wan_gw ] : [];
			ife.nameservers = wan_dns;
		}
		push(if_table, ife);

		// port_table entry. is_uplink stays false on purpose (see header).
		push(port_table, {
			port_idx: idx++,
			name: p.eth,
			mac: st.mac ?? cfg.mac,   // per-port MAC: what the switch's LLDP reports on this link
			media: 'GE',
			is_uplink: false,
			up: st.up,
			enable: true,
			autoneg: st.autoneg,
			speed: st.speed,
			full_duplex: st.full_duplex,
			rx_bytes: st.rx_bytes, rx_packets: st.rx_packets,
			rx_errors: st.rx_errors, rx_dropped: st.rx_dropped,
			rx_multicast: st.rx_multicast,
			tx_bytes: st.tx_bytes, tx_packets: st.tx_packets,
			tx_errors: st.tx_errors, tx_dropped: st.tx_dropped,
		});

	}

	data.if_table = if_table;
	data.port_table = port_table;
	data.network_table = build_network_table(cfg, dump, all_devices,
		{ name: cfg.wan_iface, iface: wan_iface, ip: wan_ip, gw: wan_gw, dns: wan_dns });

	// LLDP neighbours -> per-port mac_table + lldp_table (topology link).
	const lldp = apply_lldp(API, cfg, port_table, all_devices);
	if (length(lldp))
		data.lldp_table = lldp;

	/* ---- uplink (WAN) ---- */
	if (wan_ip) {
		const wst = dev_stats(all_devices, cfg.gw_ports[0].dev);
		data.uplink = {
			name: 'eth0',
			type: 'wire',
			up: wst.up,
			ip: wan_ip.ip,
			netmask: wan_ip.netmask,
			mac: wst.mac ?? cfg.mac,
			speed: wst.speed, max_speed: wst.speed,
			full_duplex: wst.full_duplex,
			num_port: 1,
			uptime: wan_iface?.uptime ?? 0,
			latency: latency ?? 0,
			drops: 0,
			gateways: wan_gw ? [ wan_gw ] : [],
			nameservers: wan_dns,
			rx_bytes: wst.rx_bytes, rx_packets: wst.rx_packets,
			rx_errors: wst.rx_errors, rx_dropped: wst.rx_dropped,
			tx_bytes: wst.tx_bytes, tx_packets: wst.tx_packets,
			tx_errors: wst.tx_errors, tx_dropped: wst.tx_dropped,
		};
	}

	/* ---- speedtest ---- */
	if (speedtest_enabled(cfg)) {
		poll_speedtest();
		data['speedtest-status'] = speedtest_status_obj();
		// a real USG reports whether a result is stored
		data['speedtest-status-saved'] = (st_state.result != null);
	}
}

return {
	defaults: {
		// Legacy USG-3P. If the controller rejects it or nags to upgrade,
		// switch to a UXG model code and capture that device's fields.
		// model_display should match what a real device reports.
		model: 'UGW3',
		model_display: 'UniFi Security Gateway 3P',
		hostname: 'USG',
		version: '4.4.57.5578372',
	},

	init: init,
	collect_data: collect_data,

	'cmd.speedtest': cmd_speedtest,
	'cmd.locate': cmd_locate,
};
