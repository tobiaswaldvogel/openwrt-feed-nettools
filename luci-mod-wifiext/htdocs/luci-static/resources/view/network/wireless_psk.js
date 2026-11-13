'use strict';
'require ui';
'require view';
'require dom';
'require poll';
'require uci';
'require rpc';
'require fs';
'require form';
'require tools.widgets as widgets';

const callHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

return view.extend({
	generateWpaPsk: function(length) {
		const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
		let	ret = "";
    
		// Use browser-native crypto for better security than Math.random()
		let	randomValues = new Uint32Array(length);
		window.crypto.getRandomValues(randomValues);

		for (var i = 0; i < length; i++)
			ret += charset.charAt(randomValues[i] % charset.length);

		return ret;
	},

	load: function() {
		return Promise.all([
			callHostHints(),
			uci.load('wireless').catch(function(e) {}),
			uci.load('wireless_psk').catch(function(e) {})
		]);
	},

	render: function([hosts]) {
		let m = new form.Map('wireless_psk', _('Wireless PSKs'), _('Wireless PSKs'));
                let s = m.section(form.TableSection, 'wifi-psk');
                s.anonymous = true;
                s.addremove = true;
                s.addbtntitle = _('Add new PSK ...');
                s.sortable = true;

		let comment = s.option(form.Value, 'comment', _('Comment'));

		let maco = s.option(form.Value, 'mac', _('MAC Address'));
                maco.editable = true;
		maco.datatype = 'macaddr';
		Object.keys(hosts).forEach(function(mac) {
			const lower_mac = mac.toLowerCase();
			const hint = hosts[mac].name || L.toArray(hosts[mac].ipaddrs || hosts[mac].ipv4)[0];
			maco.value(mac, hint ? '%s (%s)'.format(mac, hint) : mac);
                });
		maco.cfgvalue = function(...args) {
			let retval = form.Value.prototype.cfgvalue.call(maco, ...args);
			if (typeof retval === "string")
				 retval = retval.toUpperCase();
			return retval;
		}

		let psk = s.option(form.Value, 'psk', _('Password'));
		psk.datatype = 'wpakey';
		psk.password = true;
		psk.width= '30%';
		psk.cfgvalue = (section_id) => {
			const existing = uci.get('wireless_psk', section_id, 'psk');
			if (existing)
				return existing;

			return this.generateWpaPsk(16);
		};

		let vid = s.option(form.Value, 'vid', _('VLAN id'));
		vid.width = '10%';
		uci.sections('wireless','wifi-vlan', function(section) {
			vid.value(section.vid, section.vid + ' (' + section.name + ')' );
		});

		let iface   = s.option(form.Value, 'iface', _('Interface'));
		uci.sections('wireless','wifi-iface', function(section) {
			if (section.wpa_psk_file)
				iface.value(section.ifname, section.ifname);
		});
		iface.width = '10%';

		return m.render();
	}
});
