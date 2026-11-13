'use strict';
'require view';
'require uci';
'require rpc';
'require form';

const callHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

function generateWpaPsk(length) {
	const charset = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
	const randomValues = new Uint32Array(length);
	let ret = '';

	// browser-native crypto instead of Math.random()
	window.crypto.getRandomValues(randomValues);

	for (let i = 0; i < length; i++)
		ret += charset.charAt(randomValues[i] % charset.length);

	return ret;
}

return view.extend({
	load: function() {
		return Promise.all([
			callHostHints().catch(function(e) { return {}; }),
			uci.load('wireless').catch(function(e) {}),
			uci.load('wireless_psk').catch(function(e) {})
		]);
	},

	render: function([hosts]) {
		// interfaces whose PSKs are synced from the UniFi controller
		// (maintained by the unifi package, see sync_wpa_psks())
		const managed = L.toArray(uci.get('wireless_psk', 'unifi', 'iface'));

		const ifnames = [];
		uci.sections('wireless', 'wifi-iface', function(section) {
			if (section.wpa_psk_file && section.ifname && !ifnames.includes(section.ifname))
				ifnames.push(section.ifname);
		});

		let desc = _('Per-client WPA passphrases for wireless interfaces using a PSK file. Each passphrase can be bound to a VLAN and optionally restricted to a client MAC address and a single interface; without an interface it applies to all of them.');
		if (managed.length)
			desc += '<br /><br />' + _('The passphrases of %s are synchronized from the UniFi controller: entries for these interfaces are added, changed or removed with the next controller update. Comments and MAC addresses are kept.')
				.format(managed.map(function(i) { return '<strong>%h</strong>'.format(i); }).join(', '));

		const m = new form.Map('wireless_psk', _('Wireless PSKs'), desc);
		const s = m.section(form.TableSection, 'wifi-psk');
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('Add new PSK ...');
		s.sortable = true;

		// new entries start with a random passphrase
		s.handleAdd = function(ev, name) {
			const config_name = this.uciconfig ?? this.map.config;
			const sid = this.map.data.add(config_name, this.sectiontype, name);
			this.map.data.set(config_name, sid, 'psk', generateWpaPsk(16));
			return this.map.save(null, true);
		};

		s.option(form.Value, 'comment', _('Comment'));

		const maco = s.option(form.Value, 'mac', _('MAC Address'));
		maco.datatype = 'macaddr';
		maco.placeholder = _('any');
		Object.keys(hosts).forEach(function(mac) {
			const hint = hosts[mac].name || L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4)[0];
			maco.value(mac, hint ? '%s (%s)'.format(mac, hint) : mac);
		});
		maco.cfgvalue = function(...args) {
			const retval = form.Value.prototype.cfgvalue.apply(this, args);
			return (typeof(retval) === 'string') ? retval.toUpperCase() : retval;
		};

		const psk = s.option(form.Value, 'psk', _('Password'));
		psk.datatype = 'wpakey';
		psk.password = true;
		psk.rmempty = false;
		psk.width = '30%';

		const vid = s.option(form.Value, 'vid', _('VLAN id'));
		vid.datatype = 'range(1,4094)';
		vid.placeholder = _('none');
		vid.width = '10%';
		uci.sections('wireless', 'wifi-vlan', function(section) {
			if (section.vid)
				vid.value(section.vid, '%s (%s)'.format(section.vid, section.name || section.network || '?'));
		});

		const iface = s.option(form.Value, 'iface', _('Interface'));
		iface.placeholder = _('all');
		iface.width = '10%';
		ifnames.forEach(function(ifname) {
			iface.value(ifname, managed.includes(ifname) ? '%s (UniFi)'.format(ifname) : ifname);
		});
		iface.validate = function(section_id, value) {
			if (!value || !ifnames.length || ifnames.includes(value))
				return true;

			return _('Unknown interface, expecting one of: %s').format(ifnames.join(', '));
		};

		// The same passphrase may only appear more than once for one
		// interface/client if it maps to the same VLAN - otherwise the
		// VLAN assignment would depend on the entry order.
		const value_of = function(o, sid) {
			const v = o.formvalue(sid);
			return (v != null) ? v : (o.cfgvalue(sid) || '');
		};

		psk.validate = function(section_id, value) {
			if (!value)
				return true;

			const my_iface = value_of(iface, section_id);
			const my_mac = value_of(maco, section_id).toUpperCase();
			const my_vid = value_of(vid, section_id);

			for (const sid of s.cfgsections()) {
				if (sid == section_id || value_of(psk, sid) !== value)
					continue;

				const o_iface = value_of(iface, sid);
				const o_mac = value_of(maco, sid).toUpperCase();

				if (my_iface && o_iface && my_iface != o_iface)
					continue;

				if (my_mac && o_mac && my_mac != o_mac)
					continue;

				if (value_of(vid, sid) != my_vid)
					return _('Passphrase is already used with a different VLAN id for the same interface/client');
			}

			return true;
		};

		// changing any of the fields can make another row's passphrase
		// (in)valid, so re-check all of them
		const revalidate = function() {
			for (const sid of s.cfgsections()) {
				const el = psk.getUIElement(sid);
				if (el)
					el.triggerValidation();
			}
		};

		for (const o of [ maco, psk, vid, iface ])
			o.onchange = revalidate;

		return m.render();
	}
});
