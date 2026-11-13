'use strict';

import * as digest from 'digest';
import * as socket from 'socket';
import { readfile, open, popen } from 'fs';

const provider_name = 'netgear';

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
		err('unifi-netgear: no switch host (' + CONFIG_NAME + '.main.switch_host)\n');
		return false;
	}

    if (!cfg.switch_password) {
		err('unifi-netgear: no switch password (' + CONFIG_NAME + '.main.switch_password)\n');
		return false;
	}

	const sw_addrs = socket.addrinfo(cfg.switch_host, cfg.switch_port, {
		family: socket.AF_INET,
		protocol: socket.IPPROTO_TCP
	});

    if (!sw_addrs) {
		err('unifi-netgear: Could not resolve switch host (' + switch_host +')\n');
		return false;
	}	

    cfg.ip = sw_addrs[0].addr.address;
    if (!cfg.mac)
        cfg.mac = mac_for_ip(cfg.ip);

	if (lc(cfg.mac) == "00:00:00:00:00:00") {
		err('unifi-netgear: Could not resolve MAC address for switch\n');
		return false;
	}

	return true;
}

function netgear_merge(str1, str2) {
    let arr1 = split(str1, '');
    let arr2 = split(str2, '');
    let result = "";
    for (let index1 = 0, index2 = 0; index1 < length(arr1) || index2 < length(arr2); index1++, index2++) {
        if (index1 < length(arr1)) 
            result += arr1[index1];
        if (index2 < length(arr2))
            result += arr2[index2];
    }
    return result;
}

function netgear_parse_port_stats(ports, stats) {
	let values = match(stats, /<input type="hidden" value="([^"]*)/g);
	if (length(values) != length(ports) * 6)
		return;

	let v = 0;
	for (let port in ports) {
		port.ingress = (values[v++][1] << 32) + int(values[v++][1]);
		port.egress  = (values[v++][1] << 32) + int(values[v++][1]);
		port.errors  = (values[v++][1] << 32) + int(values[v++][1]);
	}
}

function netgear_parse_port_poe(ports, poe) {
	let values = match( poe, /<div>[^<]*<span>([^<]*)/g);
	if (length(values) != length(ports) * 5)
		return;

	let v = 0;
	for (let port in ports) {
		port.poe_voltage = values[v++][1];
		port.poe_current = values[v++][1];
		port.poe_power = values[v++][1];
		port.temperature = values[v++][1];
		port.poe_error = values[v++][1];
	}
}

function netgear_gs308ep_status(host, session, cb) {
	cb.request(host, '/dashboard.cgi', { 'Cookie': 'SID=' + session }, status => {
		cb.request(host, '/portStatistics.cgi', { 'Cookie': 'SID=' + session}, stats => {
			cb.request(host, '/getPoePortStatus.cgi', { 'Cookie': 'SID=' + session }, poe => {
				cb.request(host, '/logout.cgi', { 'Cookie': 'SID=' + session }, '', logout => {
					let ports = [];
					let ports_status = split(status.body, '<li class="list_item index_li">');

					for (let p = 1; p < length(ports_status); p++) {
						let port = {};
						let port_status = split(ports_status[p], '</li>')[0];
						let items_status = match(port_status, /<input[^>]*class="([^"]*)"[^>]*value="([^"]*)/g);

						for (let item in items_status) {
							if (length(item) >= 3) {
								let key = lc(item[1]);
								let value = item[2];

								if (key == 'portname')
									key = 'name';
								else if (key == 'flowctr')
									key = 'flowcontrol';
								port[key] = value;
							}
						}

						push(ports, port);
					}

					netgear_parse_port_stats(ports, stats.body);
					netgear_parse_port_poe(ports, poe.body);
					cb.setResult({ 'ports': ports });
				});
			});
		});
	});
}

function netgear_ecos_status(API, cfg) {
    let response_stat = API.http_request(cfg.ip, cfg.switch_port, 'GET', '/status.cgi', { 'Cookie': 'SID=' + cfg.netgear_session }, null);
    let response_portstat = API.http_request(cfg.ip, cfg.switch_port, 'GET', '/portStatistics.cgi', { 'Cookie': 'SID=' + cfg.netgear_session }, null);

    let ports = [];
    let port_status = split(response_stat.body, '<tr class="portID">');

    for (let p = 1; p < length(port_status); p++) {
        let port = {};
        
        let values = match(split(port_status[p], '</tr>')[0], /<td[^>]*>([^<\n]*)/g);
        if (length(values) > 1)
            port.port = values[1][1];
        if (length(values) > 2)
            port.name = values[2][1];
        if (length(values) > 3)
            port.status = values[3][1];
        if (length(values) > 4)
            port.speed = values[4][1];
        if (length(values) > 5)
            port.linkedspeed = values[5][1];
        if (length(values) > 6)
            port.flowcontrol = values[6][1];
        if (length(values) > 7)
            port.maxmtu = values[7][1];

        push(ports, port);
    }

    netgear_parse_port_stats(ports, response_portstat.body);
    return ports;
}

const URLENCODED_HEADER = {'Content-Type': 'application/x-www-form-urlencoded'};

function poll_switch_ports(API, cfg) {
	if (!cfg.switch_host)
		return null;

	let result, error;
	let session = cfg.netgear_session;

	if (!session) {
		API.dbg(provider_name + ': logon\n');
		/* Get model random number */
		let response = API.http_request(cfg.ip, cfg.switch_port, 'GET', '/login.cgi', null, null);

		let model;
		let rand = match(response.body, /id='rand' value='([^']*)/);
		if (length(rand) < 2 || response.status_code != 200) {
			warn('Failed to get login page');
			return null;
		}

		let model_match = match(response.body, /class="(switchInfo|p-name)"[^>]*>([^ <]*)/);
		if (length(model_match) >= 3)
			model = model_match[2];

		cfg.netear_model = model;

		let payload = 'password=' + digest.md5(netgear_merge(cfg.switch_password, rand[1])); 
		response = API.http_request(cfg.ip, cfg.switch_port, 'POST', '/login.cgi', URLENCODED_HEADER, payload);

		let cookie = match(response.headers, /Set-Cookie:.*SID=([^;]+)/);
		if (length(cookie) < 2) {
			let errmsg = match(response.body, /(id="pwdErr"|class=.pwdErrStyle)[^>]*>([^<]*)/);
			if (length(errmsg) >= 3)
				warn('Netgear logon oassword error: ' + errmsg[2]);
			else
				warn('Netgear login failed: ' + response);

			return null;
		}
    
    	session = cookie[1];
		cfg.netgear_session = session;

	}

    let ports;

    if (cfg.netgear_model == 'GS308EP') {
        API.dbg(`GS308EP detected, using netgear_gs308ep_status\n`);
        ports = netgear_gs308ep_status(API, cfg);
    } else {
        API.dbg(`ECOS detected, using netgear_ecos_status\n`);
        ports = netgear_ecos_status(API, cfg);
    }

    API.dbg(`unifi-netgear: switch poll complete, ${length(ports)} ports found\n`);
	return ports;
}

function shutdown(API, cfg) {
	if (cfg.netgear_session) {
		API.dbg(provider_name + ': logoff\n');
    	API.http_request(cfg.ip, cfg.switch_port, 'GET', '/logout.cgi', { 'Cookie': 'SID=' + cfg.netgear_session }, null);
	}
}

// Maps one entry from getSwitchPortStatus()'s ports[] (netgear's own
// field names, either from GS308EP's class-attribute scrape or ECOS's
// positional columns) into a UniFi port_table entry.
function netgear_port_to_unifi(idx, p) {
	const status_text = lc(p.status ?? p.linkstatus ?? '');
	const speed_text  = p.linkedspeed || p.speed || '';
	const speed_match = match(speed_text, /([0-9]+)\s*([MG])/i);

	let speed = 0;
	if (speed_match) {
		speed = +speed_match[1];
		if (uc(speed_match[2]) == 'G')
			speed *= 1000;
	}

	return {
		port_idx:      idx,
		name:          p.name || ('port' + idx),
		media:         'GE',
		up:            status_text != '' && !match(status_text, /down|disconnect/),
		speed:         speed,
		full_duplex:   !!match(speed_text, /full/i),
		autoneg:       true,
		is_uplink:     false,
		tx_bytes:      p.egress ?? 0,
		tx_errors:     p.errors ?? 0,
		tx_packets:    0,
		tx_dropped:    0,
		rx_bytes:      p.ingress ?? 0,
		rx_packets:    0,
		rx_errors:     0,
		rx_dropped:    0,
		rx_multicast:  0,
		mac_table:       [],
	};
}

function collect_data(API, cfg, data) {
	data.port_table = [];

	const raw_ports = poll_switch_ports(API, cfg);

	if (!raw_ports)
		return false;

	for (let i, p in raw_ports) {
		let port = netgear_port_to_unifi(i + 1, p);
		if (port.name == cfg.uplink_port || '' + port.port_idx == cfg.uplink_port)
			port.is_uplink = true;
		push(data.port_table, netgear_port_to_unifi(i + 1, p));
	}
}

return {
	defaults: {
		model: 'USF5P',
        model_display: 'USF5P',
        hostname: 'US5P',
        switch_port: '80',
        uplink_port: '5',
	},

	init: init,
	collect_data: collect_data,
	shutdown: shutdown,
};