( function () {
	'use strict';
	var CFG    = window.VH_AWS_NETWORK || { accounts: [] };
	var acctSel = document.querySelector( '[data-vh-net-account]' );
	var vpcSel  = document.querySelector( '[data-vh-net-vpc]' );
	var map     = document.querySelector( '[data-vh-net-map]' );
	var meta    = document.querySelector( '[data-vh-net-meta]' );
	if ( ! acctSel || ! map ) { return; }
	if ( ! CFG.accounts.length ) { map.innerHTML = '<div class="vh-panel"><p>No network data yet. Run the AWS integration sync, then reload.</p></div>'; return; }
	CFG.accounts.forEach( function ( a ) { var o = document.createElement( 'option' ); o.value = a; o.textContent = a; acctSel.appendChild( o ); } );

	var GRAPH = null;

	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"]/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ c ]; } ); }

	/* ---- inline icons (recognisable per service, coloured by CSS) ---- */
	function svg( inner, extra ) { return '<svg viewBox="0 0 24 24" class="vh-ico ' + ( extra || '' ) + '" aria-hidden="true">' + inner + '</svg>'; }
	var ICONS = {
		internet: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
		igw:      '<rect x="3" y="8" width="18" height="8" rx="2"/><path d="M8 8V4m0 0-2 2m2-2 2 2M16 16v4m0 0 2-2m-2 2-2-2"/>',
		tgw:      '<circle cx="12" cy="12" r="3"/><path d="M12 3v6M12 15v6M3 12h6M15 12h6M6 6l3.5 3.5M14.5 14.5 18 18M18 6l-3.5 3.5M9.5 14.5 6 18"/>',
		nat:      '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h8m0 0-3-3m3 3-3 3"/>',
		checkpoint:'<path d="M12 3 5 6v6c0 4 3 6.5 7 9 4-2.5 7-5 7-9V6l-7-3z"/><path d="m9 12 2 2 4-4"/>',
		ec2:      '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="8" y="8" width="8" height="8" rx="1"/><path d="M8 2v2M12 2v2M16 2v2M8 20v2M12 20v2M16 20v2M2 8h2M2 12h2M2 16h2M20 8h2M20 12h2M20 16h2"/>',
		lambda:   '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 7h3l5 10M16 7l-4 7"/>',
		s3:       '<path d="M5 6h14l-1.4 12.2a2 2 0 0 1-2 1.8H8.4a2 2 0 0 1-2-1.8L5 6z"/><path d="M4 6h16M9 6V4h6v2"/>',
		rds:      '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
		dynamodb: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="m11 10-2 4h3l-1 4"/>',
		alb:      '<circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="19" cy="19" r="2"/><path d="M7 12h4M11 12l6-6M11 12h6M11 12l6 6"/>',
		apigw:    '<path d="M8 4C5 4 5 9 3 12c2 3 2 8 5 8M16 4c3 0 3 5 5 8-2 3-2 8-5 8"/><circle cx="12" cy="12" r="1.4"/>',
		pcx:      '<circle cx="6" cy="12" r="2.6"/><circle cx="18" cy="12" r="2.6"/><path d="M8.6 12h6.8"/>',
		box:      '<rect x="4" y="4" width="16" height="16" rx="2"/>'
	};
	function icon( kind ) { return svg( ICONS[ kind ] || ICONS.box, 'vh-ico--' + kind ); }
	var KINDLABEL = { ec2: 'EC2', lambda: 'Lambda', s3: 'S3', rds: 'RDS', dynamodb: 'DynamoDB', alb: 'Load balancer', apigw: 'API Gateway', ecs: 'ECS' };
	function kindLabel( k ) { return KINDLABEL[ k ] || String( k || '' ).toUpperCase(); }

	function badge( cls, txt, title ) { return '<i class="vh-b ' + cls + '"' + ( title ? ' title="' + esc( title ) + '"' : '' ) + '>' + esc( txt ) + '</i>'; }

	/* Store nodes so the popup can read the full record by index. */
	var STORE = [];
	function card( node, tier ) {
		var idx = STORE.push( node ) - 1;
		var sub = tier === 'compute' && node.ip ? node.ip : ( node.kind === 'alb' && node.scheme ? node.scheme : kindLabel( node.kind ) );
		var meta2 = ( node.ip ? kindLabel( node.kind ) + ' · ' + node.ip : sub );
		var badges = '';
		if ( node.exposed ) { badges += badge( 'vh-b--pub', node.pubip ? 'public' : 'exposed', node.pubip ? 'Public IP ' + node.pubip : 'Reachable from the internet' ); }
		var t = node.ten || {};
		if ( t.c ) { badges += badge( 'vh-b--crit', t.c, t.c + ' critical (Tenable)' ); }
		if ( t.h ) { badges += badge( 'vh-b--high', t.h, t.h + ' high (Tenable)' ); }
		var p = node.ple || {};
		if ( p.c || p.h ) { badges += badge( 'vh-b--cspm', 'CSPM ' + ( ( p.c || 0 ) + ( p.h || 0 ) ), 'Plerion CSPM findings' ); }
		if ( node.state && node.state !== 'running' ) { badges += badge( 'vh-b--off', node.state, 'Instance state' ); }
		return '<button type="button" class="vh-card vh-card--' + esc( node.kind ) + ( node.exposed ? ' vh-card--exposed' : '' ) + '" data-vh-node="' + idx + '">'
			+ '<span class="vh-card__ico">' + icon( node.kind ) + '</span>'
			+ '<span class="vh-card__body"><span class="vh-card__name">' + esc( node.name ) + '</span>'
			+ '<span class="vh-card__meta">' + esc( meta2 ) + '</span></span>'
			+ '<span class="vh-card__badges">' + badges + '</span></button>';
	}

	function edgeCard( kind, title, sub, cls ) {
		return '<div class="vh-edge ' + ( cls || '' ) + '"><span class="vh-edge__ico">' + icon( kind ) + '</span>'
			+ '<span class="vh-edge__body"><span class="vh-edge__t">' + esc( title ) + '</span>'
			+ ( sub ? '<span class="vh-edge__s">' + esc( sub ) + '</span>' : '' ) + '</span></div>';
	}

	var CAP = 40;
	function column( id, title, sub, html ) {
		return '<div class="vh-col" id="vh-col-' + id + '"><div class="vh-col__h"><span class="vh-col__t">' + esc( title ) + '</span>'
			+ ( sub ? '<span class="vh-col__s">' + sub + '</span>' : '' ) + '</div>' + html + '</div>';
	}

	function kindGroups( items, tier ) {
		if ( ! items.length ) { return '<p class="vh-empty">Nothing here.</p>'; }
		var byKind = {};
		items.forEach( function ( n ) { ( byKind[ n.kind ] = byKind[ n.kind ] || [] ).push( n ); } );
		var order = [ 'ec2', 'ecs', 'lambda', 'apigw', 'alb', 'rds', 'dynamodb', 's3' ];
		var kinds = Object.keys( byKind ).sort( function ( a, b ) {
			var ia = order.indexOf( a ), ib = order.indexOf( b );
			return ( ia < 0 ? 99 : ia ) - ( ib < 0 ? 99 : ib );
		} );
		return kinds.map( function ( k ) {
			var arr = byKind[ k ];
			var crit = 0, high = 0, exposed = false;
			arr.forEach( function ( n ) { crit += ( n.ten && n.ten.c ) || 0; high += ( n.ten && n.ten.h ) || 0; if ( n.exposed ) { exposed = true; } } );
			var badges = ( exposed ? badge( 'vh-b--pub', 'exposed', 'internet-exposed resources inside' ) : '' )
				+ ( crit ? badge( 'vh-b--crit', crit, crit + ' critical (Tenable)' ) : '' )
				+ ( ! crit && high ? badge( 'vh-b--high', high, high + ' high (Tenable)' ) : '' );
			var body = arr.map( function ( n ) { return card( n, tier ); } ).join( '' );
			return '<div class="vh-kg">'
				+ '<button type="button" class="vh-kg__h vh-card--' + esc( k ) + '" data-kg-toggle aria-expanded="false">'
				+   '<span class="vh-kg__ico">' + icon( k ) + '</span>'
				+   '<span class="vh-kg__lbl">' + esc( kindLabel( k ) ) + '</span>'
				+   '<span class="vh-kg__n">' + arr.length + '</span>'
				+   '<span class="vh-kg__badges">' + badges + '</span>'
				+   '<svg class="vh-kg__chev" viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
				+ '</button>'
				+ '<div class="vh-kg__body" hidden>' + body + '</div></div>';
		} ).join( '' );
	}

	function xacctHtml( peers ) {
		peers = peers || {};
		var tgw = peers.tgw || [], pcx = peers.pcx || [];
		if ( ! tgw.length && ! pcx.length ) { return ''; }
		var h = '<div class="vh-xacct"><div class="vh-xacct__h">Cross-account connectivity</div>';
		tgw.forEach( function ( t ) {
			var chips = t.accounts.map( function ( a ) { return '<span class="vh-xacct__acct">' + esc( a ) + '</span>'; } ).join( '' );
			if ( t.count > t.accounts.length ) { chips += '<span class="vh-xacct__acct vh-xacct__acct--more">+' + ( t.count - t.accounts.length ) + ' more</span>'; }
			h += '<div class="vh-xacct__tgw"><span class="vh-xacct__ico">' + icon( 'tgw' ) + '</span><div class="vh-xacct__bd">'
				+ '<div class="vh-xacct__t"><b>Transit Gateway hub</b> <code>' + esc( t.tgw ) + '</code></div>'
				+ '<div class="vh-xacct__sub">Shares this hub with <b>' + t.count + '</b> other account' + ( t.count === 1 ? '' : 's' ) + ' — east-west traffic between them transits the gateway (and its Check Point inspection).</div>'
				+ '<div class="vh-xacct__chips">' + chips + '</div></div></div>';
		} );
		if ( pcx.length ) {
			h += '<div class="vh-xacct__sub2">Direct VPC peerings — named workload dependencies</div><div class="vh-xacct__peers">';
			h += pcx.map( function ( p ) {
				return '<div class="vh-xacct__peer"><span class="vh-xacct__ico vh-xacct__ico--pcx">' + icon( 'pcx' ) + '</span><div class="vh-xacct__bd">'
					+ '<div class="vh-xacct__t"><b>&#8596; ' + esc( p.peer ) + '</b></div>'
					+ '<div class="vh-xacct__sub">' + esc( p.name || p.pcx ) + '</div></div></div>';
			} ).join( '' );
			h += '</div>';
		}
		return h + '</div>';
	}

	function draw( g ) {
		GRAPH = g; STORE = [];
		var routing = g.routing || {}, entry = g.entry || [], compute = g.compute || [], data = g.data || [];
		if ( ! entry.length && ! compute.length && ! data.length ) {
			map.innerHTML = '<div class="vh-panel"><p>No resources inventoried for this account yet.</p></div>';
			if ( meta ) { meta.textContent = ''; }
			return;
		}
		var ec2n = compute.filter( function ( n ) { return n.kind === 'ec2'; } ).length;
		var fnn  = compute.length - ec2n;

		// ---- routing / exposure column ----
		var edge = edgeCard( 'internet', 'Internet', g.open_ports && g.open_ports.length ? 'inbound ' + g.open_ports.join( ', ' ) : 'no open ports', 'vh-edge--net' );
		if ( routing.igw ) { edge += edgeCard( 'igw', 'Internet gateway', routing.igw + ' public route(s) · direct', 'vh-edge--igw' ); }
		if ( g.inspected ) { edge += edgeCard( 'checkpoint', 'Check Point CloudGuard', 'inspects north-south traffic', 'vh-edge--chk' ); }
		if ( routing.tgw ) { edge += edgeCard( 'tgw', 'Transit Gateway', routing.tgw + ' route(s)' + ( g.tgws && g.tgws.length ? ' · ' + g.tgws.length + ' hub' : '' ), 'vh-edge--tgw' ); }
		if ( routing.nat ) { edge += edgeCard( 'nat', 'NAT gateway', routing.nat + ' outbound', 'vh-edge--nat' ); }

		var entryHtml = entry.map( function ( n ) { return card( n, 'entry' ); } ).join( '' ) || '<p class="vh-empty">Nothing internet-facing.</p>';

		var grid = '<div class="vh-net-grid">'
			+ column( 'edge', 'Internet & routing', g.inspected ? '<span class="vh-col__pill vh-col__pill--chk">inspected</span>' : '', edge )
			+ column( 'entry', 'Entry', entry.length + '', entryHtml )
			+ column( 'compute', 'Compute', ec2n + ' EC2' + ( fnn ? ' · ' + fnn + ' fn' : '' ), kindGroups( compute, 'compute' ) )
			+ column( 'data', 'Data', data.length + '', kindGroups( data, 'data' ) )
			+ '</div><svg class="vh-flow" aria-hidden="true"></svg>' + xacctHtml( g.peers );

		map.innerHTML = grid;
		if ( meta ) {
			meta.textContent = ec2n + ' EC2 · ' + fnn + ' fn · ' + entry.length + ' entry · ' + data.length + ' data — '
				+ ( g.inspected ? 'inspected via Check Point/TGW' : ( routing.igw ? 'direct via IGW' : 'private' ) );
		}
		requestAnimationFrame( drawFlows );
	}

	/* ---- animated connection lines between the columns ---- */
	function centerOf( el, box ) { var r = el.getBoundingClientRect(); return { l: r.left - box.left, r: r.right - box.left, cy: r.top - box.top + r.height / 2, top: r.top - box.top }; }
	function drawFlows() {
		var flow = map.querySelector( '.vh-flow' ); if ( ! flow || ! GRAPH ) { return; }
		var box = map.getBoundingClientRect();
		var ids = { edge: 'vh-col-edge', entry: 'vh-col-entry', compute: 'vh-col-compute', data: 'vh-col-data' };
		var pos = {};
		Object.keys( ids ).forEach( function ( k ) { var el = document.getElementById( ids[ k ] ); if ( el ) { pos[ k ] = centerOf( el, box ); } } );
		if ( ! pos.edge || ! pos.compute ) { flow.innerHTML = ''; return; }
		flow.setAttribute( 'width', box.width ); flow.setAttribute( 'height', map.scrollHeight );
		flow.setAttribute( 'viewBox', '0 0 ' + box.width + ' ' + map.scrollHeight );

		// Two bands in the gaps between columns: inbound (top, arrows right) and
		// outbound (below, arrows back left). The gaps carry no cards, so the lines
		// and their pill labels stay legible.
		var tops = [ pos.edge.top, pos.compute.top ];
		if ( pos.entry ) { tops.push( pos.entry.top ); }
		if ( pos.data ) { tops.push( pos.data.top ); }
		// Sit the inbound band level with the first card in each column rather
		// than level with the column header, so a line reads as card-to-card.
		var yIn = Math.max.apply( null, tops ) + 74;
		var yOut = yIn + 54;

		function seg( x1, x2, y, cls, mk ) {
			var tip = x2 - ( x2 > x1 ? 9 : -9 );
			return '<path class="vh-flow__l ' + cls + '" d="M' + x1 + ',' + y + ' L' + tip + ',' + y + '" marker-end="url(#' + mk + ')"/>';
		}
		function wide( t ) { return t.length * 6.3 + 16; }

		/*
		 * A pill is centred in the gap between two columns, so the gap is its
		 * whole budget. Given more label than fits we step down to a shorter
		 * wording rather than letting it overhang -- an overhanging pill used to
		 * be painted over by the next column, which is how "egress -> NAT" came
		 * out as "egress -> NA". `avail` is the measured gap; `short` is the
		 * fallback wording, and the full text stays in a <title>.
		 */
		function pill( x, y, text, cls, avail, short ) {
			var full = text;
			// A few px either side may sit over the next column's padding -- the
			// flow layer paints above the grid now, so that reads as a label on
			// top of the diagram rather than a clipped one. Never more than the
			// padding, so it cannot reach a card's contents.
			var budget = Math.max( 44, ( avail || 1e4 ) + 16 );

			if ( wide( text ) > budget && short && wide( short ) <= budget ) {
				text = short;
			}
			if ( wide( text ) > budget ) {
				var max = Math.max( 3, Math.floor( ( budget - 16 ) / 6.3 ) );
				if ( text.length > max ) { text = text.slice( 0, max - 1 ).replace( /[\s\u00b7\u2192]+$/, '' ) + '\u2026'; }
			}

			var w = Math.max( 30, wide( text ) );
			return '<g class="vh-flow__pill ' + cls + '">'
				+ ( text === full ? '' : '<title>' + esc( full ) + '</title>' )
				+ '<rect x="' + ( x - w / 2 ) + '" y="' + ( y - 10 ) + '" rx="9" width="' + w + '" height="20"/>'
				+ '<text x="' + x + '" y="' + ( y + 4 ) + '" text-anchor="middle">' + esc( text ) + '</text></g>';
		}
		function gapOf( a, b ) { return Math.abs( b - a ); }
		function mid( a, b ) { return ( a + b ) / 2; }

		var s = '<defs>'
			+ '<marker id="mkIn" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 8,4.5 0,9z" fill="#f87171"/></marker>'
			+ '<marker id="mkApp" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 8,4.5 0,9z" fill="#38bdf8"/></marker>'
			+ '<marker id="mkData" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 8,4.5 0,9z" fill="#34d399"/></marker>'
			+ '<marker id="mkOut" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto"><path d="M0,0 8,4.5 0,9z" fill="#fbbf24"/></marker>'
			+ '</defs>';
		var ports = ( GRAPH.open_ports && GRAPH.open_ports.length ) ? GRAPH.open_ports.join( ', ' ) : 'no open ports';
		var target = pos.entry || pos.compute;

		// inbound: Internet/routing -> Entry
		s += seg( pos.edge.r, target.l, yIn, 'vh-flow__l--in', 'mkIn' );
		var gEdge = gapOf( pos.edge.r, target.l );
		s += pill( mid( pos.edge.r, target.l ), yIn - 15, 'inbound ' + ports, 'vh-flow__pill--in', gEdge, ports );
		if ( GRAPH.inspected ) { s += pill( mid( pos.edge.r, target.l ), yOut + 19, 'via Check Point', 'vh-flow__pill--chk', gEdge, 'Check Point' ); }
		// app: Entry -> Compute
		if ( pos.entry ) { s += seg( pos.entry.r, pos.compute.l, yIn, 'vh-flow__l--app', 'mkApp' ); s += pill( mid( pos.entry.r, pos.compute.l ), yIn - 15, 'app traffic', 'vh-flow__pill--app', gapOf( pos.entry.r, pos.compute.l ), 'app' ); }
		// data: Compute -> Data
		if ( pos.data ) { s += seg( pos.compute.r, pos.data.l, yIn, 'vh-flow__l--data', 'mkData' ); s += pill( mid( pos.compute.r, pos.data.l ), yIn - 15, 'reads · writes', 'vh-flow__pill--data', gapOf( pos.compute.r, pos.data.l ), 'r/w' ); }

		// outbound: Compute -> (Entry gap) -> Internet, arrows pointing back left
		var natlbl = ( GRAPH.routing && GRAPH.routing.nat ) ? 'egress \u2192 NAT' : ( GRAPH.routing && GRAPH.routing.tgw ? 'egress \u2192 TGW' : 'egress' );
		var natshort = ( GRAPH.routing && GRAPH.routing.nat ) ? 'NAT' : ( GRAPH.routing && GRAPH.routing.tgw ? 'TGW' : 'egress' );
		if ( pos.entry ) {
			s += seg( pos.compute.l, pos.entry.r, yOut, 'vh-flow__l--out', 'mkOut' );
			s += seg( pos.entry.l, pos.edge.r, yOut, 'vh-flow__l--out', 'mkOut' );
			s += pill( mid( pos.entry.l, pos.edge.r ), yOut - 15, natlbl, 'vh-flow__pill--out', gapOf( pos.entry.l, pos.edge.r ), natshort );
		} else {
			s += seg( pos.compute.l, pos.edge.r, yOut, 'vh-flow__l--out', 'mkOut' );
			s += pill( mid( pos.compute.l, pos.edge.r ), yOut - 15, natlbl, 'vh-flow__pill--out', gapOf( pos.compute.l, pos.edge.r ), natshort );
		}
		flow.innerHTML = s;
	}
	var rz; window.addEventListener( 'resize', function () { clearTimeout( rz ); rz = setTimeout( drawFlows, 150 ); } );

	// Collapse / expand a kind group; heights change, so redraw the flow lines.
	map.addEventListener( 'click', function ( e ) {
		var kg = e.target.closest ? e.target.closest( '[data-kg-toggle]' ) : null;
		if ( ! kg ) { return; }
		var body = kg.parentNode.querySelector( '.vh-kg__body' );
		var open = kg.getAttribute( 'aria-expanded' ) === 'true';
		kg.setAttribute( 'aria-expanded', open ? 'false' : 'true' );
		if ( body ) { body.hidden = open; }
		kg.parentNode.classList.toggle( 'is-open', ! open );
		requestAnimationFrame( drawFlows );
	} );

	/* ---- click a resource: config + health + findings popup ---- */
	function row( k, v ) { return v == null || v === '' ? '' : '<div class="vh-pop__row"><dt>' + esc( k ) + '</dt><dd>' + v + '</dd></div>'; }
	function findingChips( t, p ) {
		var out = '';
		if ( t && t.known ) {
			out += '<div class="vh-pop__chips">'
				+ badge( 'vh-b--crit', t.c || 0, 'critical' ) + badge( 'vh-b--high', t.h || 0, 'high' )
				+ badge( 'vh-b--med', t.m || 0, 'medium' ) + badge( 'vh-b--low', t.l || 0, 'low' )
				+ '<span class="vh-pop__src">Tenable / Defender</span></div>';
		} else {
			out += '<p class="vh-pop__muted">Not matched to a Tenable / Defender asset.</p>';
		}
		if ( p && ( p.c || p.h ) ) {
			out += '<div class="vh-pop__chips">' + badge( 'vh-b--crit', p.c || 0, 'critical' ) + badge( 'vh-b--high', p.h || 0, 'high' )
				+ '<span class="vh-pop__src vh-pop__src--cspm">Plerion CSPM</span></div>';
		}
		return out;
	}
	function exposureLine( n ) {
		if ( n.kind !== 'ec2' ) { return n.exposed ? 'Flagged internet-exposed by inventory.' : 'Not internet-exposed.'; }
		if ( n.pubip ) { return 'Public IP ' + esc( n.pubip ) + ' — reachable directly from the internet' + ( n.ports && n.ports.length ? ' on ' + esc( n.ports.join( ', ' ) ) : '' ) + '.'; }
		if ( n.exposed ) { return 'Internet-open security group but no public IP — fronted by the load balancer / Check Point inspection.'; }
		return 'Private — no direct internet path. Egress via ' + ( GRAPH && GRAPH.routing && GRAPH.routing.nat ? 'NAT' : ( GRAPH && GRAPH.inspected ? 'Check Point / TGW' : 'the VPC' ) ) + '.';
	}
	function openPopup( n ) {
		var pop = document.querySelector( '.vh-pop' );
		if ( ! pop ) {
			pop = document.createElement( 'div' ); pop.className = 'vh-pop'; pop.setAttribute( 'role', 'dialog' );
			pop.innerHTML = '<div class="vh-pop__bg" data-vh-pop-close></div><div class="vh-pop__card"><button class="vh-pop__x" data-vh-pop-close aria-label="Close">&times;</button><div class="vh-pop__in"></div></div>';
			document.body.appendChild( pop );
			pop.addEventListener( 'click', function ( e ) { if ( e.target.hasAttribute( 'data-vh-pop-close' ) ) { closePopup(); } } );
		}
		var t = n.ten || {}, p = n.ple || {};
		var cfg = '';
		if ( n.kind === 'ec2' ) {
			cfg = row( 'Instance', esc( n.id ) ) + row( 'Private IP', esc( n.ip ) ) + row( 'Public IP', n.pubip ? esc( n.pubip ) : '<span class="vh-pop__muted">none (private)</span>' )
				+ row( 'State', '<span class="vh-pill vh-pill--' + ( n.state === 'running' ? 'ok' : 'off' ) + '">' + esc( n.state || 'unknown' ) + '</span>' )
				+ row( 'Subnet', esc( n.subnet ) ) + row( 'VPC', esc( n.vpc ) )
				+ row( 'Open ports', n.ports && n.ports.length ? n.ports.map( function ( x ) { return '<code>' + esc( x ) + '</code>'; } ).join( ' ' ) : '<span class="vh-pop__muted">none from 0.0.0.0/0</span>' );
		} else if ( n.kind === 'alb' ) {
			cfg = row( 'Scheme', esc( n.scheme || '' ) ) + row( 'Resource', esc( n.id ) );
		} else {
			cfg = row( 'Resource', esc( n.name ) ) + row( 'Type', kindLabel( n.kind ) );
		}
		var health = '';
		if ( t.known ) { health = row( 'Defender health', '<span class="vh-pill vh-pill--' + ( /active|healthy/i.test( t.health ) ? 'ok' : 'warn' ) + '">' + esc( t.health || 'unknown' ) + '</span>' )
			+ row( 'Lifecycle', esc( t.life ) ) + row( 'Hostname', esc( t.host ) ) + row( 'Last seen', esc( ( t.seen || '' ).replace( 'T', ' ' ) ) ); }

		pop.querySelector( '.vh-pop__in' ).innerHTML =
			'<div class="vh-pop__head"><span class="vh-pop__ico vh-ico--' + esc( n.kind ) + '">' + icon( n.kind ) + '</span>'
			+ '<div><h3>' + esc( n.name ) + '</h3><span class="vh-pop__k">' + esc( kindLabel( n.kind ) ) + ( n.exposed ? ' · <b class="vh-pop__exp">internet-exposed</b>' : '' ) + '</span></div></div>'
			+ '<p class="vh-pop__expl">' + exposureLine( n ) + '</p>'
			+ '<h4>Configuration</h4><dl class="vh-pop__dl">' + cfg + '</dl>'
			+ ( health ? '<h4>Health</h4><dl class="vh-pop__dl">' + health + '</dl>' : '' )
			+ '<h4>Findings</h4>' + findingChips( t, p );
		requestAnimationFrame( function () { pop.classList.add( 'is-open' ); } );
	}
	function closePopup() { var pop = document.querySelector( '.vh-pop' ); if ( pop ) { pop.classList.remove( 'is-open' ); } }

	map.addEventListener( 'click', function ( e ) {
		var b = e.target.closest ? e.target.closest( '[data-vh-node]' ) : null;
		if ( ! b ) { return; }
		var n = STORE[ parseInt( b.getAttribute( 'data-vh-node' ), 10 ) ];
		if ( n ) { openPopup( n ); }
	} );
	document.addEventListener( 'keydown', function ( e ) { if ( e.key === 'Escape' ) { closePopup(); } } );

	function fetchGraph() {
		var acct = acctSel.value, vpc = vpcSel.value || '';
		map.innerHTML = '<div class="vh-panel"><p>Loading ' + esc( acct ) + '…</p></div>';
		fetch( CFG.rest + '?account=' + encodeURIComponent( acct ) + ( vpc ? '&vpc=' + encodeURIComponent( vpc ) : '' ), { headers: { 'X-WP-Nonce': CFG.nonce } } )
			.then( function ( r ) { return r.json(); } )
			.then( function ( g ) { if ( ! vpc ) { fillVpcs( g.vpcs ); } draw( g ); } )
			.catch( function () { map.innerHTML = '<div class="vh-panel"><p>Could not load the graph.</p></div>'; } );
	}
	function fillVpcs( v ) {
		vpcSel.innerHTML = '<option value="">All VPCs</option>';
		Object.keys( v || {} ).forEach( function ( id ) { var o = document.createElement( 'option' ); o.value = id; o.textContent = ( v[ id ] && v[ id ] !== id ? v[ id ] + ' ' : '' ) + '(' + id + ')'; vpcSel.appendChild( o ); } );
	}

	acctSel.addEventListener( 'change', function () { vpcSel.innerHTML = '<option value="">All VPCs</option>'; fetchGraph(); } );
	vpcSel.addEventListener( 'change', fetchGraph );
	acctSel.value = CFG.accounts[0];
	fetchGraph();
}() );
