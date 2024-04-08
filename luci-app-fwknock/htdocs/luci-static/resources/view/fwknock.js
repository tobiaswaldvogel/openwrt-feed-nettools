'use strict';
'require view';
'require ui';
'require fs';
'require form';
'require uci';
'require tools.widgets as widgets';

function ping_usage(map, section_id, code, target) {
		var dppopt = map.lookupOption('digitsperping', section_id)[0];
		var dpp = dppopt.formvalue(section_id);
		var parameter = [ '-c 1 -s', '-n 1 -l' ];
		var cmd = [ 'Linux', 'Windows' ];
		for (var i = 0; i < cmd.length; i++) cmd[i] += ':';
		while (code.length > 0) {
			var psize = code.substring(0, dpp);
			if (dpp == 1) psize = '5' + psize;
			for (var i = 0; i < cmd.length; i++)
				cmd[i] += '<br/>ping %s %s %s'.format(parameter[i], psize, target);
			code = code.substring(dpp);
		}
		return '<code>%s<br/><br/>%s</code>'.format(cmd[0], cmd[1]);
};

var CBITOTPSeed = form.Value.extend({
	hexToBase32: function(hexString) {
		const hexToBinary = {
			'0': '0000', '1': '0001', '2': '0010', '3': '0011',
			'4': '0100', '5': '0101', '6': '0110', '7': '0111',
			'8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
			'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
		};

		const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

		hexString = hexString.toLowerCase();
		var binaryString = '';
		for (var i = 0; i < hexString.length; i++)
			binaryString += hexToBinary[hexString[i]];

		var result = '';
		for (var i = 0; i < binaryString.length; i += 5) {
			var chunk = binaryString.substr(i, 5);
			while (chunk.length < 5) chunk += '0';
        		result += base32Chars[parseInt(chunk, 2)];
		}

		while (result.length % 8 !== 0) result += '=';
		return result;
	},

	renderOtp: function(section_id, alg, digits, period, seed, host) {
		var map = this.map;
		var otp = map.findElement('id', 'otp.' + this.cbid(section_id));
		var desc = otp.nextElementSibling;
		L.resolveDefault(fs.exec_direct('/usr/bin/oathtool', ['--totp=' + alg, '-d', digits, '-s', period, seed]), null).then(function (res) {
			if (res) {
				var code = res.trim();
				otp.innerHTML = _('Current OTP: %s').format(code);
				desc.innerHTML = ping_usage(map, section_id, code, host);
			} else {
				otp.innerHTML = _('OTP code could not be generated');
				desc.innerHTML = '';
			}
		});
	},


	renderQR: function(have_qrencode, section_id, alg, digits, period, seed, host) {
		const errorTemplate = '<span style="padding: 1em 0 1em 0;"><b>%s</b></span>';
		var qrContainer = this.map.findElement('id', 'qr.' + this.cbid(section_id)); 

		if (!have_qrencode) {
			qrContainer.innerHTML = errorTemplate.format(_('Install package qrencode for QR code'));
			return;
		}

		const qrTemplate = 'otpauth://totp/%s:%s?secret=%s&algorithm=%s&digits=%d&period=%d';
		var qr = qrTemplate.format(host, _('Knock'), this.hexToBase32(seed), alg, digits, period);
		L.resolveDefault(fs.exec_direct('/usr/bin/qrencode', ['--inline', '--8bit', '--type=SVG', '--output=-', qr]), null).then(function (res) {
			qrContainer.innerHTML = res ? res.trim() : errorTemplate.format(_('The QR-Code could not be generated!'));
		});
	},

	renderWidget: function(section_id, option_index, cfgvalue) {
                var value = (cfgvalue != null) ? cfgvalue : this.default,
                    widget;

		widget = new ui.Textfield(Array.isArray(value) ? value.join(' ') : value, {
			id: this.cbid(section_id),
			password: this.password,
			optional: this.optional || this.rmempty,
			datatype: this.datatype,
			placeholder: this.placeholder,
			validate: L.bind(this.validate, this, section_id),
			disabled: (this.readonly != null) ? this.readonly : this.map.readonly
		});

		var nodes = widget.render();

		nodes.append(E('button', {
			'class': 'cbi-button',
			'click': ui.createHandlerFn(this, function() {
				const hex = '0123456789ABCDEF';
				var seed = '';
				for (var i = 0; i < 40; ++i)
					seed += hex.charAt(Math.floor(Math.random() * hex.length));
				widget.setValue(seed);
				widget.triggerValidation();
			}),
			'disabled': (this.readonly != null) ? this.readonly : this.map.readonly
		}, _('Generate')));

		return E([], [
			nodes,
			E('div', { 'id' : 'qr.' + this.cbid(section_id) }),
			E('span', { 'id' : 'otp.' + this.cbid(section_id) })
		]);
	}
});

return view.extend({
	validate_time: function(section_id, time) {
		if (time != '' && !time.match(/^[0-9]+(s|m|h)$/))
			return _('Expecting: Number with unit s,m, or h');
		return true;
	},

	load: function() {
		return Promise.all([
			L.resolveDefault(fs.stat('/usr/bin/oathtool'), null),
			L.resolveDefault(fs.stat('/usr/bin/qrencode'), null),
			L.resolveDefault(fs.exec_direct('/usr/bin/uptime', [ '-s' ])),
			L.resolveDefault(fs.exec_direct('/bin/dmesg', [ '-r' ])),
			uci.load('ddns').catch(function(e) {}),
			uci.load('system').catch(function(e) {})
		]);
        },

	render: function(data) {
		var host = '';
		var have_oathtool = data[0] != null;
		var have_qrencode = data[1] != null;

		uci.sections('ddns','service', function(section) { host = section.domain; });
		if (!host)
			uci.sections('system','system', function(section) { host = section.hostname; });


		var m = new form.Map('fwknock', _('Firewall knocking'));
		var s = m.section(form.GridSection, 'knock', _('Knock definition'), _('Knock definition for opening a TCP port.'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('Add new kock definition ...');
		s.sortable = true;
		s.modaltitle = _('Knock definition');
		s.nodescriptions = true;

		var o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.editable = true;
		o.default = 1;

		o = s.option(form.DynamicList, 'port', _('TCP ports'), _('TCP ports to open after knocking'));
                o.addremove = true
                o.datatype = 'port';

		var type = s.option(form.ListValue, 'type', _('Knock type'));
		type.value('ping', _('ICMP echo request size (ping)'));
		type.value('port', _('Port sequence'));

		var target = s.option(form.ListValue, 'target', _('Target'));
                target.value('redirect', _('Redirect (dnat)'));
                target.value('input', _('This device (input)'));

		o = s.option(form.Value, 'dest_ip', _('Destination IP'));
		o.datatype = 'ipmask4';
		o.depends({ target: 'redirect' });
		o = s.option(form.Value, 'dest_port', _('Port'), _('Destination port'));
                o.datatype = 'port';
		o.depends({ target: 'redirect' });

		o = s.option(form.Value, 'timeout_knock', _('Knock sequence timeout'), _('Timeout to abort the sequence'));
		o.modalonly = true;
		o.default = '5s';
		o.validate = this.validate_time;

		o = s.option(form.Value, 'timeout_connect', _('Connect timeout'), _('Timeout for closing port after first connect'));
		o.modalonly = true;
		o.default = '0s';
		o.validate = this.validate_time;

		var mech_desc = have_oathtool ? _('Static code or TOTP (RFC 6238)') : '<b>%s</b>'.format(_('Install package oathtool for TOTP (RFC 6238)'));
		var mech = s.option(form.ListValue, 'mech', _('Code type'), mech_desc);
		mech.value('static', _('Static'));
		if (have_oathtool)
			mech.value('totp', _('TOTP'));
		mech.depends({ type: 'ping' });

		var digitsperping = s.option(form.ListValue, 'digitsperping', _('Digits per ping'),_('How many digits are encoded in each ping'));
		digitsperping.value('3', _('3 (Packet size 0-999'));
		digitsperping.value('2', _('2 (Packet size 0-99'));
		digitsperping.value('1', _('1 (Packet size 50-59'));
		digitsperping.default = 3;
		digitsperping.depends({ type: 'ping' });
		digitsperping.modalonly = true;

		var period = s.option(form.ListValue, 'period', _('TOTP period'),_('Lifetime of a OTP'));
		period.value('60', _('60 seconds'));
		period.value('30', _('30 seconds'));
		period.modalonly = true;
		period.depends({ mech: 'totp' });
		period.default = 60;

		var alg = s.option(form.ListValue, 'alg', _('TOTP algorithm'));
		alg.value('sha1', _('sha1 hmac'));
		alg.modalonly = true;
		alg.depends({ mech: 'totp' });

		var seed = s.option(CBITOTPSeed, 'seed', _('TOTP seed'),_(' '));
		seed.modalonly = true;
		seed.depends({ mech: 'totp' });
		seed.validate = function(section_id, seed) {
			var elem = this.getUIElement(section_id).node.nextElementSibling;
	                if (seed != '' && !seed.match(/^[0-9A-Fa-f]{40}$/)) {
				elem.innerHTML = '';
	      	                return _('Expecting: 40 digit hex string');
			}

			var digits = 6;
			var period = this.map.lookupOption('period', section_id)[0].formvalue(section_id);
			var alg = this.map.lookupOption('alg', section_id)[0].formvalue(section_id);
			this.renderQR(have_qrencode, section_id, alg, digits, period, seed, host);
			this.renderOtp(section_id, alg, digits, period, seed, host);
			return true;
	        };

		var code = s.option(form.Value, 'code', _('Knock code'),_('code'));
		code.modalonly = true;
		code.depends({ mech: 'static' });
		code.validate = function(section_id, code) {
			var desc = this.map.findElement('id', this.cbid(section_id)).nextElementSibling;
			desc.innerHTML = ping_usage(this.map, section_id, code, host);
			return true;
		};

		o = s.option(form.DynamicList, 'knock_port', _('Knock port sequence'));
                o.addremove = true
		o.depends({ type: 'port' });
                o.datatype = 'port';

		o = s.option(form.DynamicList, 'exception', _('Exceptions'), _('Ports which do no reset the knock sequence.<br/>E.g. 443 if you want to knock with Chrome,<br/> as it always tries 443 as well'));
                o.addremove = true
                o.datatype = 'port';
		o.modalonly = true;
		o.depends({ type: 'port' });

		var l = m.section(form.NamedSection, 'log');

		var uptime = new Date(data[2]).getTime();
		l.knocks = []
		for (var match of data[3].matchAll(/(.*)\[(.*)\](.*)knock(.*)accepted:(.*)SRC=([^\ ]*)(.*)/g)) {
			var ts = new Date(uptime + 1000 * parseFloat(match[2]));
			var ts_str = '%04d-%02d-%02d %02d:%02d:%02d'.format(
				ts.getFullYear(), ts.getMonth(), ts.getDate(),
				ts.getHours(), ts.getMinutes(), ts.getSeconds());
			l.knocks.unshift('%s: %sknock%sfrom %s accepted'.format(ts_str, match[3], match[4], match[6]));
		}

		l.render = function(view, section_id) {
			return E([], [
				E('h2', {}, [ _('Knock Log') ]),
				E('div', { 'id': 'content_syslog' }, [
					E('textarea', {
						'id': 'syslog',
						'style': 'font-size:12px',
						'readonly': 'readonly',
						'wrap': 'off',
						'rows': this.knocks.length + 1
					}, [ this.knocks.join('\n') ]),
				])
			]);			
		};

		return m.render();
	}
});
