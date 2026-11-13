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

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('wireless').catch(function(e) {}),
			uci.load('network').catch(function(e) {})
		]);
	},

	render: function(data) {
		let m = new form.Map('wireless', _('Wireless VLAN'), _('Wireless VLAN'));
                let s = m.section(form.TableSection, 'wifi-vlan');
                s.anonymous = true;
                s.addremove = true;
                s.addbtntitle = _('Add new wireless VLAN ...');
                s.sortable = true;

                let vid = s.option(form.Value, 'vid', _('VLAN id'));
		let name = s.option(form.Value, 'name', _('Name'));

                let network = s.option(form.Value, 'network', _('Network'));
		uci.sections('network','interface', function(section) {
			let name = section['.name'];
			network.value(name, name);
		});

		let iface   = s.option(form.Value, 'iface', _('Interface'));
                uci.sections('wireless','wifi-iface', function(section) {
                        iface.value(section.ifname, section.ifname);
                });

		return m.render();
	}
});
