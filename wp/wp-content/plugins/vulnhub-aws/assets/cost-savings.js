/* Cost Savings planner. Suggestions come from /vulnhub-aws/v1/cost/savings;
   every accept / drop is saved server-side (shared, audited). */
( function () {
	'use strict';
	var CFG  = window.VH_AWS_COST || {};
	var root = document.querySelector( '[data-vh-savings]' );
	if ( ! root ) { return; }

	var D = null, DEC = {}, open = {}, ticks = {};
	var f = { q: '', acct: '', cat: '', status: 'all' };
	var CAT = { idle: 'Idle instance', stopped: 'Stopped, still billed', address: 'Unused Elastic IP', volume: 'Unattached disk', schedule: 'Put on schedule', storage: 'Storage type', rightsize: 'Rightsize', modernise: 'Newer generation', review: 'Spend review' };

	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"']/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ]; } ); }
	function money( x ) { if ( x == null || isNaN( x ) ) { return '—'; } var n = Number( x ), d = Math.abs( n ) < 100 ? 2 : 0; return '$' + n.toLocaleString( undefined, { minimumFractionDigits: d, maximumFractionDigits: d } ); }
	function api( path, opts ) {
		opts = opts || {};
		if ( CFG.offline ) {
			var d = CFG.data && CFG.data[ path ];
			return d ? Promise.resolve( JSON.parse( JSON.stringify( d ) ) ) : Promise.reject( new Error( 'Not available in an exported file.' ) );
		}
		return fetch( CFG.rest + path, { method: opts.method || 'GET', credentials: 'same-origin', headers: { 'X-WP-Nonce': CFG.nonce, 'Content-Type': 'application/json' }, body: opts.body ? JSON.stringify( opts.body ) : undefined } )
			.then( function ( r ) { return r.json().then( function ( j ) { if ( ! r.ok ) { throw new Error( j && j.message ? j.message : 'HTTP ' + r.status ); } return j; } ); } );
	}
	function statusOf( id ) { return ( DEC[ id ] && DEC[ id ].status ) || ''; }
	function all() { return D ? D.confirmed.concat( D.verify ) : []; }
	var DAYS = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ];
	function weekGrid( grid ) {
		var weeks = Math.max( 1, Math.round( ( ( D.meta.window && D.meta.window.possible && D.meta.window.possible.all ) || 336 ) / 168 ) );
		var h = '<div class="vh-week" role="img" aria-label="Hours running by weekday and hour">';
		for ( var d = 0; d < 7; d++ ) {
			h += '<span>' + DAYS[ d ] + '</span>';
			for ( var hr = 0; hr < 24; hr++ ) { var n = grid[ d ][ hr ] || 0; h += '<i class="' + ( n >= weeks ? 'l2' : n > 0 ? 'l1' : '' ) + '" title="' + DAYS[ d ] + ' ' + ( hr < 10 ? '0' : '' ) + hr + ':00 — ran in ' + n + ' of ' + weeks + ' weeks"></i>'; }
		}
		return h + '</div><div class="vh-week__legend"><span><i class="l2"></i>ran every week</span><span><i class="l1"></i>some weeks</span><span><i></i>not running</span><span>(' + esc( D.meta.timezone ) + ')</span></div>';
	}

	/* ------------------------------------------------------------- load */
	function load() {
		api( '/savings' ).then( function ( d ) { D = d; DEC = d.decisions || {}; if ( Array.isArray( DEC ) ) { DEC = {}; } render(); } ).catch( function ( e ) {
			root.innerHTML = '<div class="vh-cost-notice vh-cost-notice--bad">Could not load suggestions: ' + esc( e.message ) + '</div>';
		} );
	}

	function decide( rec, status ) {
		if ( ! CFG.canDecide ) { return; }
		if ( CFG.offline ) {
			// What-if only: an exported file never writes back to VulnHub.
			var ne = root.querySelector( '[data-note="' + cssq( rec.id ) + '"]' );
			if ( status ) {
				DEC[ rec.id ] = { status: status, note: ne ? ne.value : '', by: 'you (this file only)', at: new Date().toISOString().slice( 0, 16 ).replace( 'T', ' ' ), title: rec.title, saving: rec.saving, kind: rec.kind, account: rec.account_name };
			} else {
				delete DEC[ rec.id ];
			}
			renderSummary(); renderLists(); renderPlan();
			return;
		}
		var noteEl = root.querySelector( '[data-note="' + cssq( rec.id ) + '"]' );
		var note = noteEl ? noteEl.value : ( DEC[ rec.id ] && DEC[ rec.id ].note ) || '';
		var card = root.querySelector( '[data-rec="' + cssq( rec.id ) + '"]' );
		if ( card ) { card.style.opacity = '.7'; }
		api( '/decision', { method: 'POST', body: { id: rec.id, status: status, note: note } } ).then( function ( r ) {
			if ( r.decision ) { DEC[ rec.id ] = r.decision; } else { delete DEC[ rec.id ]; }
			renderSummary();
			renderLists();
			renderPlan();
		} ).catch( function ( e ) {
			if ( card ) { card.style.opacity = ''; }
			window.alert( 'Could not save: ' + e.message );
		} );
	}
	function clearGone( id ) {
		if ( CFG.offline ) { delete DEC[ id ]; D.gone = D.gone.filter( function ( g ) { return g.id !== id; } ); renderSummary(); renderPlan(); return; }
		api( '/decision', { method: 'POST', body: { id: id, status: '' } } ).then( function () { delete DEC[ id ]; D.gone = D.gone.filter( function ( g ) { return g.id !== id; } ); renderSummary(); renderPlan(); } );
	}
	function cssq( s ) { return String( s ).replace( /"/g, '\\"' ); }

	/* ----------------------------------------------------------- render */
	function render() {
		var m = D.meta || {};
		if ( ! m.has_data ) {
			root.innerHTML = '<div class="vh-cost-notice">No cost data yet. Open <a href="' + esc( CFG.costUrl ) + '">AWS Cost</a> and press <b>Refresh from AWS</b> first.</div>';
			return;
		}
		var ctx = D.context || {}, h = '';
		h += '<div class="vh-cost-bar"><span>Suggestions from the read of <b>' + esc( m.generated ) + '</b> (' + esc( m.generated_ago ) + ') · ' + m.cost_ok + ' of ' + m.accounts + ' accounts</span><span class="vh-cost-bar__spacer"></span><a class="vh-btn" href="' + esc( CFG.costUrl ) + '">AWS Cost dashboard</a></div>';
		if ( CFG.offline ) { h += '<div class="vh-cost-notice"><b>Exported snapshot.</b> Decisions made in VulnHub before the export are shown as they were. Accept and Drop still work here, as a what-if to total up a plan and download it as CSV — nothing in this file is saved back to VulnHub.</div>'; }
		else if ( ! CFG.canDecide ) { h += '<div class="vh-cost-notice">You can view suggestions; accepting or dropping them needs the Manage or Triage permission.</div>'; }
		h += '<div class="vh-sav-sticky"><div class="vh-sav-plan" data-summary></div></div>';
		if ( ctx.ec2_covered > 0 ) {
			h += '<div class="vh-cost-notice" style="margin-top:12px"><b>How to read the figures.</b> Savings are monthly at the AWS on-demand list price (730 hours a month). Last month ' + money( ctx.ec2_covered ) + ' of EC2 compute was covered by a Savings Plan or reservation and ' + money( ctx.ec2_on_demand ) + ' was billed on demand. A compute reduction comes off the on-demand part first; beyond that it frees plan commitment for other usage rather than lowering the bill straight away. Storage, address and disk savings are not affected by the plan.</div>';
		}
		var accts = Array.from( new Set( all().map( function ( r ) { return r.account_name || r.account; } ) ) ).sort();
		var cats = Array.from( new Set( all().map( function ( r ) { return r.category; } ) ) );
		h += '<div class="vh-cost-filter" style="margin-top:12px"><input type="search" placeholder="Search suggestions, instances, IDs" aria-label="Search" data-f="q"><select data-f="acct" aria-label="Account"><option value="">All accounts</option>' + accts.map( function ( a ) { return '<option>' + esc( a ) + '</option>'; } ).join( '' ) + '</select><select data-f="cat" aria-label="Type"><option value="">All types</option>' + cats.map( function ( c ) { return '<option value="' + esc( c ) + '">' + esc( CAT[ c ] || c ) + '</option>'; } ).join( '' ) + '</select><span class="vh-seg" role="group" aria-label="Status">' + [ [ 'all', 'All' ], [ 'open', 'Open' ], [ 'accepted', 'Accepted' ], [ 'dismissed', 'Dropped' ] ].map( function ( s ) { return '<button type="button" data-status="' + s[ 0 ] + '" aria-pressed="' + ( f.status === s[ 0 ] ) + '">' + s[ 1 ] + '</button>'; } ).join( '' ) + '</span></div>';
		h += '<div class="vh-sav-section"><h2>Confirmed savings</h2><p>Every input is measured (CloudWatch, EC2 inventory) or from the AWS Price List. Open a suggestion to see the data and the arithmetic.</p></div><div class="vh-sav-list" data-list="confirmed"></div>';
		h += '<div class="vh-sav-section"><h2>Needs confirmation</h2><p>These depend on something that cannot be measured from here. Each lists what to check. Where the saving is still arithmetic on measured data it is shown as “if confirmed”; where it is not, only today’s cost is shown. If it turns out not to be needed, drop it.</p></div><div class="vh-sav-list" data-list="verify"></div>';
		h += '<div class="vh-sav-section"><h2>Your plan</h2><p>Everything accepted, with who accepted it and when.</p></div><div data-plan></div>';
		root.innerHTML = h;

		root.querySelectorAll( '[data-f]' ).forEach( function ( el ) {
			var k = el.getAttribute( 'data-f' );
			el.value = f[ k ];
			el.addEventListener( k === 'q' ? 'input' : 'change', function () { f[ k ] = el.value; renderLists(); } );
		} );
		root.querySelectorAll( '[data-status]' ).forEach( function ( b ) {
			b.addEventListener( 'click', function () {
				f.status = b.getAttribute( 'data-status' );
				root.querySelectorAll( '[data-status]' ).forEach( function ( x ) { x.setAttribute( 'aria-pressed', String( x === b ) ); } );
				renderLists();
			} );
		} );
		renderSummary();
		renderLists();
		renderPlan();
	}

	function renderSummary() {
		var el = root.querySelector( '[data-summary]' );
		if ( ! el ) { return; }
		var acc = { n: 0, t: 0 }, co = { n: 0, t: 0 }, vo = { n: 0, t: 0, ne: 0 }, dis = 0;
		all().forEach( function ( r ) {
			var s = statusOf( r.id ), v = r.saving || 0;
			if ( s === 'accepted' ) { acc.n++; acc.t += v; } else if ( s === 'dismissed' ) { dis++; } else if ( r.kind === 'confirmed' ) { co.n++; co.t += v; } else { vo.n++; vo.t += v; if ( r.saving == null ) { vo.ne++; } }
		} );
		( D.gone || [] ).forEach( function ( g ) { if ( g.status === 'accepted' ) { acc.n++; acc.t += g.saving || 0; } } );
		el.innerHTML =
			'<div class="vh-tile vh-tile--good"><span class="vh-tile__label">Accepted plan</span><span class="vh-tile__value">' + money( acc.t ) + '<span class="vh-muted" style="font-size:13px;font-weight:500"> /month</span></span><span class="vh-tile__meta">' + money( acc.t * 12 ) + ' a year · ' + acc.n + ' accepted</span></div>' +
			'<div class="vh-tile vh-tile--neutral"><span class="vh-tile__label">Confirmed, still open</span><span class="vh-tile__value">' + money( co.t ) + '<span class="vh-muted" style="font-size:13px;font-weight:500"> /month</span></span><span class="vh-tile__meta">' + co.n + ' suggestions</span></div>' +
			'<div class="vh-tile vh-tile--warning"><span class="vh-tile__label">Needs confirmation</span><span class="vh-tile__value">' + money( vo.t ) + '<span class="vh-muted" style="font-size:13px;font-weight:500"> /month if confirmed</span></span><span class="vh-tile__meta">' + vo.n + ' open · ' + vo.ne + ' with no estimate (cost shown only)</span></div>' +
			'<div class="vh-tile vh-tile--neutral"><span class="vh-tile__label">Dropped</span><span class="vh-tile__value">' + dis + '</span><span class="vh-tile__meta">not needed or not applicable</span></div>';
	}

	function matches( r ) {
		var s = statusOf( r.id );
		if ( f.status === 'open' && s ) { return false; }
		if ( f.status === 'accepted' && s !== 'accepted' ) { return false; }
		if ( f.status === 'dismissed' && s !== 'dismissed' ) { return false; }
		if ( f.acct && ( r.account_name || r.account ) !== f.acct ) { return false; }
		if ( f.cat && r.category !== f.cat ) { return false; }
		if ( f.q ) {
			var hay = ( r.title + ' ' + r.name + ' ' + r.resource + ' ' + r.account_name + ' ' + r.account + ' ' + r.action ).toLowerCase();
			if ( hay.indexOf( f.q.toLowerCase() ) < 0 ) { return false; }
		}
		return true;
	}

	function renderLists() {
		[ 'confirmed', 'verify' ].forEach( function ( kind ) {
			var el = root.querySelector( '[data-list="' + kind + '"]' );
			if ( ! el ) { return; }
			var list = D[ kind ].filter( matches );
			if ( ! list.length ) {
				el.innerHTML = '<div class="vh-sav-empty">' + ( D[ kind ].length ? 'Nothing matches the filters.' : ( kind === 'confirmed' ? 'No confirmed savings in the current data.' : 'Nothing needs confirmation in the current data.' ) ) + '</div>';
				return;
			}
			el.innerHTML = list.map( card ).join( '' );
			list.forEach( function ( r ) { wireCard( el, r ); } );
		} );
	}

	function card( r ) {
		var s = statusOf( r.id ), dec = DEC[ r.id ], isV = r.kind === 'verify';
		var cls = 'vh-sav' + ( s === 'accepted' ? ' is-accepted' : s === 'dismissed' ? ' is-dismissed' : '' );
		var money_html = r.saving != null
			? '<b>' + money( r.saving ) + '</b><span>' + ( isV ? 'a month if confirmed' : 'a month' ) + '</span>'
			: '<b>' + money( r.current ) + '</b><span>a month today · saving not estimated</span>';
		var meta = '<span class="vh-sav__pill">' + esc( CAT[ r.category ] || r.category ) + '</span>' + ( r.account_name ? '<span>' + esc( r.account_name ) + '</span>' : '' ) + ( r.region ? '<span>· ' + esc( r.region ) + '</span>' : '' ) + ( r.env ? '<span>· ' + esc( r.env ) + '</span>' : '' ) + ( r.saving != null && r.current != null && r.current !== r.saving ? '<span>· costs ' + money( r.current ) + '/month today</span>' : '' );
		var status = '';
		if ( s ) {
			status = '<span class="vh-sav__status">' + ( s === 'accepted' ? '<span class="ok">✓ Accepted</span>' : 'Dropped' ) + ' by ' + esc( dec.by ) + '</span>';
		}
		var btns = '';
		if ( s ) {
			btns = '<button type="button" class="vh-btn" data-act="" ' + dis() + '>Undo</button>';
		} else if ( isV ) {
			var all_ticked = r.checks.every( function ( _c, i ) { return ticks[ r.id + ':' + i ]; } );
			btns = '<button type="button" class="vh-btn vh-btn--primary" data-act="accepted" ' + ( CFG.canDecide && all_ticked ? '' : 'disabled' ) + ' title="' + ( all_ticked ? 'Accept' : 'Tick each check in the details first' ) + '">Confirmed — accept</button><button type="button" class="vh-btn" data-act="dismissed" ' + dis() + '>Not needed — drop</button>';
		} else {
			btns = '<button type="button" class="vh-btn vh-btn--primary" data-act="accepted" ' + dis() + '>Accept</button><button type="button" class="vh-btn" data-act="dismissed" ' + dis() + '>Drop</button>';
		}
		var h = '<article class="' + cls + '" data-rec="' + esc( r.id ) + '"><div class="vh-sav__row"><div class="vh-sav__main"><button type="button" class="vh-sav__title" aria-expanded="' + ( open[ r.id ] ? 'true' : 'false' ) + '">' + ( open[ r.id ] ? '▾ ' : '▸ ' ) + esc( r.title ) + '</button><div class="vh-sav__meta">' + meta + '</div></div><div class="vh-sav__side"><div class="vh-sav__money">' + money_html + '</div><div><div class="vh-sav__actions">' + btns + '</div>' + status + '</div></div></div>';
		if ( open[ r.id ] ) { h += detail( r ); }
		return h + '</article>';
	}
	function dis() { return CFG.canDecide ? '' : 'disabled title="Needs the Manage or Triage permission"'; }

	function detail( r ) {
		var h = '<div class="vh-sav__detail">';
		if ( r.basis ) { h += '<div><h4>' + ( r.saving != null ? 'How the saving is worked out' : 'Saving' ) + '</h4><div class="vh-sav__basis">' + esc( r.basis ) + '</div></div>'; }
		h += '<div><h4>Data it is based on</h4><table class="vh-sav__ev"><tbody>' + r.evidence.map( function ( e ) { return '<tr><td>' + esc( e[ 0 ] ) + '</td><td>' + esc( e[ 1 ] ) + '</td></tr>'; } ).join( '' ) + '</tbody></table></div>';
		if ( r.grid ) { h += '<div><h4>When it ran, last 14 days</h4>' + weekGrid( r.grid ) + '</div>'; }
		if ( r.checks && r.checks.length ) {
			h += '<div><h4>What to check before accepting</h4><ul class="vh-sav__checks">' + r.checks.map( function ( c, i ) { var k = r.id + ':' + i; return '<li><label><input type="checkbox" data-tick="' + esc( k ) + '"' + ( ticks[ k ] ? ' checked' : '' ) + '> <span>' + esc( c ) + '</span></label></li>'; } ).join( '' ) + '</ul></div>';
		}
		h += '<div><h4>What to do</h4><div>' + esc( r.action ) + '</div></div>';
		var dec = DEC[ r.id ];
		h += '<div class="vh-sav__note"><h4>Note</h4><textarea data-note="' + esc( r.id ) + '" placeholder="Owner, ticket, or why it was dropped (saved with the decision)" ' + ( CFG.canDecide ? '' : 'disabled' ) + '>' + esc( dec ? dec.note : '' ) + '</textarea>' + ( dec ? '<div class="row"><button type="button" class="vh-btn" data-save-note ' + dis() + '>Save note</button><span class="vh-muted" style="font-size:12px">' + esc( dec.status === 'accepted' ? 'Accepted' : 'Dropped' ) + ' by ' + esc( dec.by ) + ' · ' + esc( dec.at ) + ' UTC</span></div>' : '' ) + '</div>';
		h += '<div class="vh-muted" style="font-size:11.5px">ID <code>' + esc( r.id ) + '</code>' + ( r.resource ? ' · resource <code>' + esc( r.resource ) + '</code>' : '' ) + ( r.account ? ' · account <code>' + esc( r.account ) + '</code>' : '' ) + '</div>';
		return h + '</div>';
	}

	function wireCard( list, r ) {
		var el = list.querySelector( '[data-rec="' + cssq( r.id ) + '"]' );
		if ( ! el ) { return; }
		el.querySelector( '.vh-sav__title' ).addEventListener( 'click', function () { open[ r.id ] = ! open[ r.id ]; rerender( el, r ); } );
		el.querySelectorAll( '[data-act]' ).forEach( function ( b ) { b.addEventListener( 'click', function () { decide( r, b.getAttribute( 'data-act' ) ); } ); } );
		el.querySelectorAll( '[data-tick]' ).forEach( function ( c ) { c.addEventListener( 'change', function () { ticks[ c.getAttribute( 'data-tick' ) ] = c.checked; rerender( el, r ); } ); } );
		var sn = el.querySelector( '[data-save-note]' );
		if ( sn ) { sn.addEventListener( 'click', function () { decide( r, statusOf( r.id ) ); } ); }
	}
	function rerender( el, r ) {
		var ta = el.querySelector( '[data-note]' ), keep = ta ? ta.value : null;
		var tmp = document.createElement( 'div' );
		tmp.innerHTML = card( r );
		var fresh = tmp.firstChild;
		el.replaceWith( fresh );
		if ( keep !== null ) { var t2 = fresh.querySelector( '[data-note]' ); if ( t2 ) { t2.value = keep; } }
		wireCard( fresh.parentNode, r );
	}

	/* -------------------------------------------------------------- plan */
	function renderPlan() {
		var el = root.querySelector( '[data-plan]' );
		if ( ! el ) { return; }
		var rows = all().filter( function ( r ) { return statusOf( r.id ) === 'accepted'; } ).map( function ( r ) { return { r: r, d: DEC[ r.id ], gone: false }; } );
		( D.gone || [] ).forEach( function ( g ) { if ( g.status === 'accepted' ) { rows.push( { r: { id: g.id, title: g.title, account_name: g.account, saving: g.saving, kind: g.kind, action: '' }, d: g, gone: true } ); } } );
		if ( ! rows.length ) { el.innerHTML = '<div class="vh-sav-empty">Nothing accepted yet. Accept a suggestion above and it appears here with a running total.</div>'; return; }
		var tot = rows.reduce( function ( a, x ) { return a + ( x.r.saving || 0 ); }, 0 );
		var h = '<div class="vh-cost-card"><div class="vh-cost-card__head"><h2>' + rows.length + ' accepted · ' + money( tot ) + ' a month · ' + money( tot * 12 ) + ' a year</h2><span class="vh-cost-bar__spacer"></span><button type="button" class="vh-btn" data-csv>Download CSV</button></div><div class="vh-cost-scroll"><table class="vh-cost-table"><thead><tr><th>Suggestion</th><th>Account</th><th class="r">Saving / month</th><th>Accepted</th><th>Status</th></tr></thead><tbody>';
		rows.forEach( function ( x ) {
			h += '<tr><td>' + esc( x.r.title ) + '<span class="sub">' + ( x.r.kind === 'verify' ? 'needed confirmation' : 'confirmed' ) + ( x.d.note ? ' · ' + esc( x.d.note ) : '' ) + '</span></td><td>' + esc( x.r.account_name ) + '</td><td class="r">' + ( x.r.saving == null ? 'not estimated' : money( x.r.saving ) ) + '</td><td>' + esc( x.d.by ) + '<span class="sub">' + esc( x.d.at ) + ' UTC</span></td><td>' + ( x.gone ? 'No longer in the latest data — likely done <button type="button" class="vh-btn" style="min-height:26px;padding:2px 8px;font-size:11.5px" data-clear="' + esc( x.r.id ) + '" ' + dis() + '>Clear</button>' : 'Still present in the latest data' ) + '</td></tr>';
		} );
		h += '</tbody></table></div></div>';
		el.innerHTML = h;
		el.querySelector( '[data-csv]' ).addEventListener( 'click', function () { csv( rows ); } );
		el.querySelectorAll( '[data-clear]' ).forEach( function ( b ) { b.addEventListener( 'click', function () { clearGone( b.getAttribute( 'data-clear' ) ); } ); } );
	}

	function csv( rows ) {
		var q = function ( s ) { s = String( s == null ? '' : s ); return /[",\n]/.test( s ) ? '"' + s.replace( /"/g, '""' ) + '"' : s; };
		var out = [ [ 'Suggestion', 'Type', 'Account', 'Account ID', 'Region', 'Resource', 'Saving per month (USD)', 'Saving per year (USD)', 'Accepted by', 'Accepted at (UTC)', 'Note', 'What to do', 'Still in latest data' ].join( ',' ) ];
		rows.forEach( function ( x ) {
			out.push( [ x.r.title, x.r.kind === 'verify' ? 'Needed confirmation' : 'Confirmed', x.r.account_name, x.r.account || '', x.r.region || '', x.r.resource || '', x.r.saving == null ? '' : x.r.saving.toFixed( 2 ), x.r.saving == null ? '' : ( x.r.saving * 12 ).toFixed( 2 ), x.d.by, x.d.at, x.d.note, x.r.action, x.gone ? 'no' : 'yes' ].map( q ).join( ',' ) );
		} );
		var blob = new Blob( [ out.join( '\n' ) ], { type: 'text/csv' } ), a = document.createElement( 'a' );
		a.href = URL.createObjectURL( blob );
		a.download = 'aws-savings-plan-' + new Date().toISOString().slice( 0, 10 ) + '.csv';
		document.body.appendChild( a ); a.click(); a.remove();
		setTimeout( function () { URL.revokeObjectURL( a.href ); }, 1000 );
	}

	load();
}() );

