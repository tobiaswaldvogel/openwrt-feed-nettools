'use strict';
'require baseclass';
'require fs';
'require uci';
'require network';

var pibs = {};
var plc_iface;

return baseclass.extend({
	title: _('Powerline Communication (PLC)'),

	resolve_pib: function(mac, callback, ctx) {
		var tmpfile = '/tmp/plc_' + mac.replaceAll(':','_') + '.pib';
		L.resolveDefault(fs.exec_direct('/usr/bin/plctool', [ '-i', plc_iface, '-p', tmpfile, mac ]), null).then(function (data) {
			L.resolveDefault(fs.exec_direct('/usr/bin/chkpib', [ '-v', tmpfile ]), null).then(function (pib_data) {
				var pib = { };

				if (pib_data ) {
					let pib_lines = pib_data.split('\n');
	
					for (var i = 0; i < pib_lines.length; i++) {
						let line = pib_lines[i].trim();
						if (line.startsWith('---'))
							continue;
	
						let key = line.substring(0,3);
						let value = line.substring(4);
	
						if (key == 'USR')
							pib.usr = value;

						if (key == 'MFG')
							pib.mfg = value;
					}

				}

				if (!('usr' in pib))
					pib.usr = 'PLC Adapter';

				pib.mac = mac;
				pibs[mac] = pib;

				if (callback)
					callback(pib, ctx)
			})
		});
	},

    desc_adapter: function(pib) {
		var desc = pib.usr + ' ' + pib.mac;;
		if ('mfg' in pib)
			desc = desc + ' (' + pib.mfg + ')';
		return desc;
	},

	render_adapter: function(adapter, net_widget, active) {
		let id = 'plc_' + adapter.mac.replaceAll(':','_');
		var desc;

		if (adapter.mac in pibs)
			desc = this.desc_adapter(pibs[adapter.mac]);
		 else {
			desc = adapter.mac;

			this.resolve_pib(adapter.mac, function(pib, ctx) {
				let adapter_widget = document.getElementById(id);
				let item = adapter_widget.firstChild;
				item.innerText = ctx.desc_adapter(pib);
			}, this);
		}

		return E('div', { class: 'ifacebox' }, [
			E('div', { 'id' : id, class: 'ifacebox-head center ' + (active ? 'active' : '') },
			E('strong', desc)),
			net_widget
		]);
	},

	render_network: function(network, stations_widget) {
		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td left' }, [ network.nid ]),
			E('td', { 'class': 'td left' }, [ network.role ]), 
			E('td', { 'class': 'td left' }, [ stations_widget ]) 
		]);
	},
	
	render_station: function(station) {
		let id = 'plc_' + station.mac.replaceAll(':','_');
		var desc = '-';
		var mfg = '-';

		if (station.mac in pibs) {
			let pib = pibs[station.mac];
			if ('usr' in pib)
				desc = pib.usr;
			if ('mfg' in pib)
				mfg = pib.mfg;
		} else {
			this.resolve_pib(station.mac, function(pib, ctx) {
				let station_widget = document.getElementById(id);
//				let item = adapter_widget.firstChild;
//				item.innerText = pib.usr + ' ' + mac;
			}, this);
		}

		return  E('div', { 'id' : id }, renderBadge(
			L.resource('icons/ethernet.png'), null,
			_('Station'), station.mac,
			_('Name'), desc,
			_('Model'), mfg,
			_('RX'), station.rx,
			_('TX'), station.tx,
		))
	},
	
	load: function() {
		return Promise.all([
				network.getNetwork('lan'),
				uci.load('plc').catch(function(e) {})
			]).then(function(data) {
				uci.sections('plc','plc', function(section) { if ('interface' in section) plc_iface = section.interface; });
				if (typeof plc_iface === 'undefined')
					plc_iface = data[0].getDevice().device;

				return Promise.all([ fs.exec_direct('/usr/bin/plctool', ['-m', '-i', plc_iface]) ]);
			})
	},

	render: function(data) {
		let roleRegExp = /\(([^)]+)\)/;
		let lines =	data[0].split('\n');

		var	i,
			adapter = { },
			network = { },
			station = {},
			active;

		let network_widget_template =
			E('table', { 'id': 'plc_network', 'class': 'table' }, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, _('Network ID')),
					E('th', { 'class': 'th' }, _('Role')),
					E('th', { 'class': 'th' }, _('Stations')),
				])
			]);

		let stations_widget_template = E('div', {});
		let netstatus = E('div', { 'class': 'network-status-table' });

		let network_widget  = network_widget_template;
		let stations_widget = stations_widget_template;

		for (i = 0; i < lines.length; i++) {
			let item = lines[i].split('=');
			if (item.length < 2)
				continue;

			let key = item[0].trim();
			let value = item[1].trim();

			if (key == "source address") {
				if (station.mac) {
					stations_widget.appendChild(this.render_station(station));
					active = true;
				}
		
				if (network.nid)
					network_widget.appendChild(this.render_network(network, stations_widget));
		
				if (adapter.mac)
					netstatus.appendChild(this.render_adapter(adapter, network_widget, true));
		
				network_widget  = network_widget_template;
				stations_widget = stations_widget_template;
				adapter = { mac: value };
				network = { };
				station = { };
				active = false;

			} else if (key == 'network->NID')
				network.nid = value;

			else if (key == 'network->ROLE')
				network.role = roleRegExp.exec(value)[1];

			else if (key == 'station->MAC' ) {
				if (station.mac) {
					stations_widget.appendChild(this.render_station(station));
					active = true;
				}

				station = { mac: value};

			} else if (key == 'station->AvgPHYDR_TX')
				station.tx = value;

			else if (key == 'station->AvgPHYDR_RX')
				station.rx = value;
		}

		if (station.mac) {
			stations_widget.appendChild(this.render_station(station));
			active = true;
		}

		if (network.nid)
			network_widget.appendChild(this.render_network(network, stations_widget));
		
		if (adapter.mac)
			netstatus.appendChild(this.render_adapter(adapter, network_widget, true));

		return netstatus;
	}
});
