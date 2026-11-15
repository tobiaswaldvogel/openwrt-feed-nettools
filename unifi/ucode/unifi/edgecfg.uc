'use strict';

/*
 * A gateway receives its system_cfg as one JSON document (an EdgeOS-style
 * config tree). To keep it readable and editable in /etc/config/unifi, it is
 * stored as a UCI list with one line per leaf, the path written like an
 * EdgeOS "set" command:
 *
 *   system login user admin authentication public-keys tw key=AAAA...
 *   firewall group network-group corporate_network network[]=192.168.1.0/24
 *   system conntrack timeout icmp:=30
 *
 *   <path>=<string>       string value, taken verbatim up to the line end
 *   <path>:=<json>        any other value (number, boolean, {}, []), or a
 *                         subtree whose keys can't be written as a path
 *   <path>[]=... / []:=   one element of an array, in order
 *
 * Path elements are separated by single spaces. unflatten(flatten(x)) gives
 * back x exactly.
 */

// Keys that can't be a path element: they'd be ambiguous when parsed back
// (a ':' only right before the '=', where it marks a JSON value).
function path_safe(k) {
	return length(k) && !match(k, /[ \t\r\n=]/) && substr(k, -1) != ':' && substr(k, -2) != '[]';
}

function scalar_line(path, v) {
	if (type(v) == 'string' && !match(v, /[\r\n]/))
		return `${path}=${v}`;
	return sprintf('%s:=%J', path, v);
}

function flatten_into(out, path, v) {
	if (type(v) == 'object') {
		const ks = keys(v);
		if (!length(ks) || (path && length(filter(ks, k => !path_safe(k))))) {
			push(out, sprintf('%s:=%J', path, v));
			return;
		}
		for (let k in ks) {
			if (!path_safe(k)) {        // only possible at the root
				warn(`unifi: system_cfg key "${k}" dropped\n`);
				continue;
			}
			flatten_into(out, path ? `${path} ${k}` : k, v[k]);
		}
		return;
	}

	if (type(v) == 'array') {
		if (!length(v)) {
			push(out, `${path}:=[]`);
			return;
		}
		for (let e in v)
			push(out, (type(e) == 'object' || type(e) == 'array')
				? sprintf('%s[]:=%J', path, e)
				: scalar_line(path + '[]', e));
		return;
	}

	push(out, scalar_line(path, v));
}

function flatten(tree) {
	let out = [];
	flatten_into(out, '', tree);
	return out;
}

function unflatten(lines) {
	let root = {};

	for (let line in (lines ?? [])) {
		const eq = index(line, '=');
		if (eq < 1)
			continue;

		let path = substr(line, 0, eq);
		let val = substr(line, eq + 1);

		const is_json = substr(path, -1) == ':';
		if (is_json) {
			path = substr(path, 0, -1);
			try { val = json(val); } catch (e) { continue; }
		}

		const is_elem = substr(path, -2) == '[]';
		if (is_elem)
			path = substr(path, 0, -2);

		const ks = split(path, ' ');
		let node = root;
		for (let i = 0; i < length(ks) - 1; i++) {
			if (type(node[ks[i]]) != 'object')
				node[ks[i]] = {};
			node = node[ks[i]];
		}

		const last = ks[-1];
		if (is_elem) {
			if (type(node[last]) != 'array')
				node[last] = [];
			push(node[last], val);
		} else {
			node[last] = val;
		}
	}

	return root;
}

return { flatten, unflatten };
