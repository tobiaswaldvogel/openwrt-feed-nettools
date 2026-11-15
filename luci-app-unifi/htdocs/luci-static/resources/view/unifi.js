'use strict';
'require view';
'require uci';
'require rpc';
'require form';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

const PROVIDERS = {
	openwrt:    _('This device as access point'),
	openwrt_gw: _('This device as gateway (experimental)'),
	tplink:     _('TP-Link Easy Smart switch'),
	netgear:    _('Netgear Plus switch'),
};

// "mgmt_cfg_c46e1f735642" -> "c4:6e:1f:73:56:42"
function section_mac(name) {
	const m = /_([0-9a-f]{12})$/.exec(name);
	return m ? m[1].match(/../g).join(':') : null;
}

// controller-managed keys are stored with '.' replaced by '___'
function ctrl_get(section, key) {
	return uci.get('unifi', section, key.replace(/\./g, '___'));
}

// SSIDs with WPA PSKs in a system_cfg section (aaa.N.* = hostapd config),
// same selection as get_wpa_psks() in the openwrt provider
function psk_ssids_of(s) {
	const ssids = [];

	for (const k in s) {
		const m = /^aaa___(\d+)___ssid$/.exec(k);
		if (!m || ssids.includes(s[k]) || s['aaa___' + m[1] + '___status'] == 'disabled')
			continue;

		if (s['aaa___' + m[1] + '___wpa___psk_file___status'] == 'enabled' || s['aaa___' + m[1] + '___wpa___psk'])
			ssids.push(s[k]);
	}

	return ssids;
}

return view.extend({
	load: function() {
		return Promise.all([
			callServiceList('unifi').catch(function() { return {}; }),
			uci.load('unifi'),
			uci.load('wireless').catch(function() {}),
			uci.load('wireless_psk').then(function() { return true; }, function() { return false; }),
			uci.load('network').catch(function() {})
		]);
	},

	render: function([ services, , , has_wireless_psk ]) {
		const instances = services?.unifi?.instances ?? {};

		// SSIDs using a PSK file locally, and SSIDs with PSKs on the controller
		const local_ssids = [];
		uci.sections('wireless', 'wifi-iface', function(s) {
			if (s.wpa_psk_file && s.ssid && !local_ssids.includes(s.ssid))
				local_ssids.push(s.ssid);
		});

		const ctrl_ssids = [];
		uci.sections('unifi', 'system_cfg', function(s) {
			for (const ssid of psk_ssids_of(s))
				if (!ctrl_ssids.includes(ssid))
					ctrl_ssids.push(ssid);
		});

		// selectable SSIDs: local ones plus anything already configured
		const choice_ssids = local_ssids.slice();
		uci.sections('unifi', 'instance_cfg', function(s) {
			for (const ssid of L.toArray(s.psk_ssid))
				if (!choice_ssids.includes(ssid))
					choice_ssids.push(ssid);
		});

		const m = new form.Map('unifi', _('UniFi'),
			_('Emulates UniFi devices so that this OpenWrt device (as access point or gateway), or switches monitored by it, show up in and can be adopted by a UniFi Network controller.'));

		/* ---------------------------------------------------------------- */
		/* instances                                                        */
		/* ---------------------------------------------------------------- */

		let s = m.section(form.GridSection, 'instance_cfg', _('Instances'),
			_('Each instance is one emulated device. Changes restart the emulator.'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.addbtntitle = _('Add instance');

		s.tab('general', _('General'));
		s.tab('device', _('Device'));
		s.tab('switch', _('Switch'));
		s.tab('gateway', _('Gateway'));
		s.tab('wireless', _('Wireless'));

		let o;

		o = s.taboption('general', form.DummyValue, '_status', _('Status'));
		o.modalonly = false;
		o.cfgvalue = function(sid) {
			if (uci.get('unifi', sid, 'enabled') == '0')
				return _('disabled');

			return instances[sid]?.running ? _('running') : _('not running');
		};

		o = s.taboption('general', form.Flag, 'enabled', _('Enabled'));
		o.default = o.enabled;
		o.editable = true;

		o = s.taboption('general', form.ListValue, 'provider', _('Emulated device'));
		for (const p in PROVIDERS)
			o.value(p, PROVIDERS[p]);
		o.default = 'openwrt';

		o = s.taboption('general', form.Value, 'unifi_host', _('Controller'),
			_('Host name or address of the UniFi controller.'));
		o.datatype = 'host';
		o.placeholder = 'unifi';

		o = s.taboption('general', form.Value, 'unifi_service', _('Inform port'));
		o.datatype = 'port';
		o.placeholder = '8080';
		o.modalonly = true;

		o = s.taboption('general', form.Value, 'inform_ip', _('Inform address'),
			_('Overrides the address resolved from the controller host name.'));
		o.datatype = 'ip4addr';
		o.modalonly = true;

		o = s.taboption('general', form.Value, 'interval', _('Inform interval'),
			_('Seconds between two informs, unless the controller requests otherwise.'));
		o.datatype = 'uinteger';
		o.placeholder = '60';
		o.modalonly = true;

		o = s.taboption('general', form.Flag, 'debug', _('Debug logging'));
		o.modalonly = true;

		o = s.taboption('general', form.Flag, 'ssh_keys', _('Use controller SSH keys'),
			_('Add the SSH keys of the controller (Device SSH Authentication) to the authorized keys of this device. They are kept in a separate block, locally configured keys remain; disabling this removes them again.'));
		o.depends('provider', 'openwrt');
		o.depends('provider', 'openwrt_gw');
		o.depends('provider', '');
		o.modalonly = true;

		/* device */

		o = s.taboption('device', form.Value, 'hostname', _('Name'),
			_('Default device name, until the controller assigns one.'));
		o.placeholder = _('provider default');
		o.modalonly = true;

		o = s.taboption('device', form.Value, 'mac', _('MAC address'),
			_('Identity towards the controller. Detected automatically if empty; changing it makes the device show up as a new one.'));
		o.datatype = 'macaddr';
		o.placeholder = _('automatic');
		o.modalonly = true;

		o = s.taboption('device', form.Value, 'model', _('Model'));
		o.placeholder = _('provider default');
		o.modalonly = true;

		o = s.taboption('device', form.Value, 'model_display', _('Model display name'));
		o.placeholder = _('provider default');
		o.modalonly = true;

		o = s.taboption('device', form.Value, 'uplink_dev', _('Uplink device'),
			_('Network device reported as uplink port.'));
		o.placeholder = _('automatic');
		o.depends('provider', 'openwrt');
		o.depends('provider', '');
		o.modalonly = true;

		o = s.taboption('device', form.Value, 'uplink_peer', _('Uplink peer MAC'),
			_('MAC address of the upstream device, added to the uplink port to show the topology.'));
		o.datatype = 'macaddr';
		o.depends('provider', 'openwrt');
		o.depends('provider', '');
		o.modalonly = true;

		o = s.taboption('device', form.DynamicList, 'lldp', _('Static neighbours'),
			_('"<MAC> <port index>": devices to report as connected to a port.'));
		o.placeholder = 'aa:bb:cc:dd:ee:ff 1';
		o.modalonly = true;
		o.validate = function(sid, value) {
			if (!value || /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\s+\d+$/.test(value.trim()))
				return true;

			return _('Expecting "<MAC> <port index>"');
		};

		/* switch */

		o = s.taboption('switch', form.Value, 'switch_host', _('Switch address'));
		o.datatype = 'host';
		o.rmempty = false;
		o.depends('provider', 'tplink');
		o.depends('provider', 'netgear');
		o.modalonly = true;

		o = s.taboption('switch', form.Value, 'switch_port', _('Switch HTTP port'));
		o.datatype = 'port';
		o.placeholder = '80';
		o.depends('provider', 'tplink');
		o.depends('provider', 'netgear');
		o.modalonly = true;

		o = s.taboption('switch', form.Value, 'switch_username', _('Switch user'));
		o.placeholder = 'admin';
		o.depends('provider', 'tplink');
		o.modalonly = true;

		o = s.taboption('switch', form.Value, 'switch_password', _('Switch password'));
		o.password = true;
		o.rmempty = false;
		o.depends('provider', 'tplink');
		o.depends('provider', 'netgear');
		o.modalonly = true;

		o = s.taboption('switch', form.Value, 'uplink_port', _('Uplink port'),
			_('Switch port name or number connected upstream.'));
		o.placeholder = '5';
		o.depends('provider', 'tplink');
		o.depends('provider', 'netgear');
		o.modalonly = true;

		/* gateway (openwrt_gw provider) */

		o = s.taboption('gateway', form.Value, 'wan_iface', _('WAN interface'),
			_('Network interface reported as WAN (eth0); the other physical ports become eth1 and eth2.'));
		o.placeholder = 'wan';
		uci.sections('network', 'interface', function(iface) {
			if (iface['.name'] != 'loopback')
				o.value(iface['.name']);
		});
		o.depends('provider', 'openwrt_gw');
		o.modalonly = true;

		o = s.taboption('gateway', form.DynamicList, 'phys_port', _('Physical ports'),
			_('Network devices of the physical ports. Detected automatically if empty.'));
		o.placeholder = 'eth0';
		o.depends('provider', 'openwrt_gw');
		o.modalonly = true;

		o = s.taboption('gateway', form.Flag, 'speedtest', _('Speed test'),
			_('Allow the controller to run WAN speed tests.'));
		o.default = o.enabled;
		o.depends('provider', 'openwrt_gw');
		o.modalonly = true;

		o = s.taboption('gateway', form.Value, 'speedtest_bin', _('Speed test client'),
			_('Ookla <code>speedtest</code> or <code>librespeed-cli</code>, as name or full path.'));
		o.value('speedtest');
		o.value('librespeed-cli');
		o.placeholder = _('automatic');
		o.depends({ provider: 'openwrt_gw', speedtest: '1' });
		o.modalonly = true;

		o = s.taboption('gateway', form.Value, 'speedtest_server', _('Speed test server'));
		o.placeholder = _('automatic');
		o.depends({ provider: 'openwrt_gw', speedtest: '1' });
		o.modalonly = true;

		for (const caps of [ 'fw_caps', 'fw2_caps', 'hw_caps', 'wifi_caps' ]) {
			o = s.taboption('gateway', form.Value, caps, caps,
				(caps == 'fw_caps') ? _('Capability bitfields reported to the controller, as captured with <code>mca-dump</code> on a real gateway. Not reported if empty.') : null);
			o.datatype = 'uinteger';
			o.depends('provider', 'openwrt_gw');
			o.modalonly = true;
		}

		/* wireless: radio settings */

		o = s.taboption('wireless', form.Flag, 'radio_sync', _('Use controller radio settings'),
			_('Apply the radio settings of the controller to the local radios: channel (or automatic selection with the allowed channels and DFS usage), channel width and transmit power. Changes restart the affected radios, which briefly disconnects their clients.'));
		o.depends('provider', 'openwrt');
		o.depends('provider', '');
		o.modalonly = true;

		/* wireless: neighbour scan */

		o = s.taboption('wireless', form.Flag, 'scan', _('Scan for neighbouring networks'),
			_('Reports the networks around to the controller. The channels are scanned one at a time with short off-channel visits, so that connected clients are not affected.'));
		o.default = o.enabled;
		o.depends('provider', 'openwrt');
		o.depends('provider', '');
		o.modalonly = true;

		o = s.taboption('wireless', form.Value, 'scan_interval', _('Scan interval'),
			_('Seconds between two scans of one channel (plus the operating channel). All channels are covered after one interval per channel.'));
		o.datatype = 'min(5)';
		o.placeholder = '60';
		o.depends('scan', '1');
		o.modalonly = true;

		o = s.taboption('wireless', form.Value, 'scan_max_load', _('Scan load limit'),
			_('kbit/s of traffic on a radio above which no scan is started on it.'));
		o.datatype = 'uinteger';
		o.placeholder = '5000';
		o.depends('scan', '1');
		o.modalonly = true;

		/* wireless: PSKs */

		o = s.taboption('wireless', form.Flag, 'psk_sync', _('Use controller PSKs'),
			has_wireless_psk
				? _('Synchronize the WPA passphrases (including private PSKs with VLAN) of the controller into the local wireless PSK configuration for wireless networks with the same SSID. The last synchronized passphrases remain configured when this is disabled or the controller configuration is removed.')
				: _('Requires luci-mod-wifiext (wireless PSK configuration), which is not installed.'));
		o.default = o.enabled;
		o.depends('provider', 'openwrt');
		o.depends('provider', '');
		o.modalonly = true;

		o = s.taboption('wireless', form.MultiValue, 'psk_ssid', _('SSIDs'),
			_('Wireless networks using the controller PSKs. If none is selected, all SSIDs known to the controller are used.'));
		o.placeholder = _('all');
		o.depends('psk_sync', '1');
		o.retain = true;    // keep the selection while the sync is disabled
		o.modalonly = true;
		for (const ssid of choice_ssids) {
			let label = ssid;
			if (!local_ssids.includes(ssid))
				label += ' (' + _('not configured locally') + ')';
			else if (!ctrl_ssids.includes(ssid))
				label += ' (' + _('no PSKs on controller') + ')';
			o.value(ssid, label);
		}

		o = s.taboption('wireless', form.DummyValue, '_psk', _('Controller PSKs'));
		o.modalonly = false;
		o.cfgvalue = function(sid) {
			const provider = uci.get('unifi', sid, 'provider') ?? 'openwrt';
			if (provider != 'openwrt' || !has_wireless_psk)
				return '-';

			if (uci.get('unifi', sid, 'psk_sync') == '0')
				return _('disabled');

			const sel = L.toArray(uci.get('unifi', sid, 'psk_ssid'));
			return sel.length ? sel.join(', ') : _('all SSIDs');
		};

		/* ---------------------------------------------------------------- */
		/* adoption state, written by the emulator                          */
		/* ---------------------------------------------------------------- */

		s = m.section(form.TableSection, 'mgmt_cfg', _('Adopted devices'),
			_('Adoption state received from the controller, per emulated device MAC address. Removing an entry forgets the adoption: the device restarts unadopted and has to be adopted again (or forgotten on the controller).'));
		s.anonymous = true;
		s.addremove = true;
		s.renderSectionAdd = function() { return E([]); };

		s.handleRemove = function(sid, ev) {
			const sys = sid.replace(/^mgmt_cfg_/, 'system_cfg_');
			this.map.data.remove('unifi', sid);
			if (sys != sid && uci.get('unifi', sys))
				this.map.data.remove('unifi', sys);

			return this.map.save(null, true);
		};

		o = s.option(form.DummyValue, '_mac', _('MAC address'));
		o.cfgvalue = function(sid) { return section_mac(sid) ?? sid; };

		o = s.option(form.DummyValue, '_name', _('Name'));
		o.cfgvalue = function(sid) {
			return ctrl_get(sid.replace(/^mgmt_cfg_/, 'system_cfg_'), 'resolv.host.1.name') ?? '-';
		};

		o = s.option(form.DummyValue, '_controller', _('Controller'));
		o.cfgvalue = function(sid) {
			const url = uci.get('unifi', sid, 'mgmt_url');
			try {
				return url ? new URL(url).host : '-';
			} catch (e) {
				return url;
			}
		};

		o = s.option(form.DummyValue, '_state', _('State'));
		o.cfgvalue = function(sid) {
			return uci.get('unifi', sid, 'authkey') ? _('adopted') : _('pending');
		};

		o = s.option(form.DummyValue, '_ssids', _('SSIDs with PSKs'));
		o.cfgvalue = function(sid) {
			const ssids = psk_ssids_of(uci.get('unifi', sid.replace(/^mgmt_cfg_/, 'system_cfg_')) ?? {});
			return ssids.length ? ssids.join(', ') : '-';
		};

		return m.render();
	}
});
