'use strict';
'require view';
'require fs';
'require form';
'require uci';
'require tools.widgets as widgets';

return view.extend({
	validate_time: function(section_id, time) {
		if (time != '' && !time.match(/^[0-9]+(s|m|h)$/))
			return _('Expecting: Number with unit s,m, or h');
		return true;
	},

	render: function(stats) {
		var m = new form.Map('portknock', _('Port knocking'));
		var s = m.section(form.GridSection, 'knock', _('Knock sequences'), _('Port knock sequences for opening a TCP port.'));
		s.anonymous = true;
		s.addremove = true;
		s.addbtntitle = _('Add new kock sequence ...');
		s.sortable = true;
		s.modaltitle = _('Port knock sequence');
		s.nodescriptions = true;

		var o = s.option(form.Value, 'port', _('TCP port'),_('TCP port to open after completing the knock sequence'));
                o.datatype = 'port';

		var o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.editable = true;
		o.default = 1;

		var target = s.option(form.ListValue, 'target', _('Target'));
                target.value('redirect', _('Redirect (dnat)'));
                target.value('input', _('This device (input)'));

		o = s.option(form.Value, 'dest_ip', _('Destination IP'));
		o.datatype = 'ipmask4';
		o.depends({ target: 'redirect' });
		o = s.option(form.Value, 'dest_port', _('Port'), _('Destination port'));
                o.datatype = 'port';
		o.depends({ target: 'redirect' });

		o = s.option(form.Value, 'timeout_knock', _('Knock sequence timeout'), _('Timeout after which the sequence will be aborted'));
		o.modalonly = true;
		o.validate = this.validate_time;
		o = s.option(form.Value, 'timeout_connect', _('Connect timeout'), _('Timeout for closing port after first connect'));
		o.modalonly = true;

		o = s.option(form.DynamicList, 'knock_port', _('Knock sequence'));
                o.addremove = true
                o.datatype = 'port';

		o = s.option(form.DynamicList, 'exception', _('Exceptions'), _('Ports which do no reset the knock sequence.<br/>E.g. 443 if you want to knock with Chrome,<br/> as it always tries 443 as well'));
                o.addremove = true
                o.datatype = 'port';
		o.modalonly = true;

		return m.render();
	}
});
