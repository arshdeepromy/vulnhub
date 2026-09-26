/* AWS Cost dashboard. Reads /vulnhub-aws/v1/cost; never calls AWS itself. */
( function () {
	'use strict';
	var CFG  = window.VH_AWS_COST || {};
	var root = document.querySelector( '[data-vh-cost]' );
	if ( ! root ) { return; }

	var DATA = null;
	var state = { acctSort: 'last_month', acctDir: -1, acctQ: '', acctEnv: '', open: {}, schedAcct: '', chartTable: false };

	/* ---------------------------------------------------------- helpers */
	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"']/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ c ]; } ); }
	function money( x, cents ) {
		if ( x == null || isNaN( x ) ) { return '—'; }
		var n = Number( x ), d = cents || Math.abs( n ) < 100 ? 2 : 0;
		return ( n < 0 ? '−$' : '$' ) + Math.abs( n ).toLocaleString( undefined, { minimumFractionDigits: d, maximumFractionDigits: d } );
	}
	function pct( a, b ) { if ( ! b ) { return ''; } var p = ( a - b ) / b * 100; return ( p >= 0 ? '+' : '−' ) + Math.abs( p ).toFixed( 0 ) + '%'; }
	function dayLabel( d ) { var t = new Date( d + 'T00:00:00Z' ); return t.toLocaleDateString( undefined, { day: 'numeric', month: 'short', timeZone: 'UTC' } ); }
	function api( path, opts ) {
		opts = opts || {};
		// An exported file carries its data with it and never calls the server.
		if ( CFG.offline ) {
			var d = CFG.data && CFG.data[ path || '' ];
			return d ? Promise.resolve( JSON.parse( JSON.stringify( d ) ) ) : Promise.reject( new Error( 'Not available in an exported file.' ) );
		}
		return fetch( CFG.rest + ( path || '' ), {
			method: opts.method || 'GET',
			credentials: 'same-origin',
			headers: { 'X-WP-Nonce': CFG.nonce, 'Content-Type': 'application/json' },
			body: opts.body ? JSON.stringify( opts.body ) : undefined
		} ).then( function ( r ) { return r.json().then( function ( j ) { if ( ! r.ok ) { throw new Error( j && j.message ? j.message : 'HTTP ' + r.status ); } return j; } ); } );
	}
	var DAYS = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ];
	function weekGrid( grid, weeks ) {
		if ( ! grid ) { return '<span class="vh-muted">—</span>'; }
		var h = '<div class="vh-week" role="img" aria-label="Hours running by weekday and hour">';
		for ( var d = 0; d < 7; d++ ) {
			h += '<span>' + DAYS[ d ] + '</span>';
			for ( var hr = 0; hr < 24; hr++ ) {
				var n = grid[ d ][ hr ] || 0, cls = n >= weeks ? 'l2' : ( n > 0 ? 'l1' : '' );
				h += '<i class="' + cls + '" title="' + DAYS[ d ] + ' ' + ( hr < 10 ? '0' : '' ) + hr + ':00 — ran in ' + n + ' of ' + weeks + ' weeks"></i>';
			}
		}
		return h + '</div>';
	}
	function weekLegend( weeks ) {
		return '<div class="vh-week__legend"><span><i class="l2"></i>ran every week (' + weeks + ' of ' + weeks + ')</span><span><i class="l1"></i>ran some weeks</span><span><i></i>not running</span></div>';
	}

	/* ------------------------------------------------------------- load */
	function load() {
		return api( '' ).then( function ( d ) { DATA = d; render(); } ).catch( function ( e ) {
			root.innerHTML = '<div class="vh-cost-notice vh-cost-notice--bad">Could not load cost data: ' + esc( e.message ) + '</div>';
		} );
	}

	/* ---------------------------------------------------------- refresh */
	var poll = null;
	function refresh() {
		api( '/refresh', { method: 'POST' } ).then( function () { watch(); } ).catch( function ( e ) { alertBar( e.message ); } );
	}
	function watch() {
		clearTimeout( poll );
		api( '/progress' ).then( function ( m ) {
			DATA = DATA || {};
			var was = DATA.meta && DATA.meta.running;
			DATA.meta = Object.assign( {}, DATA.meta || {}, m );
			renderBar();
			if ( m.running ) { poll = setTimeout( watch, 4000 ); } else if ( was || ( m.progress && m.progress.state === 'done' ) ) { load(); }
		} );
	}
	function alertBar( msg ) {
		var el = root.querySelector( '[data-bar-msg]' );
		if ( el ) { el.textContent = msg; }
	}

	/* ----------------------------------------------------------- render */
	function renderBar() {
		var m = ( DATA && DATA.meta ) || {}, el = root.querySelector( '[data-bar]' );
		if ( ! el ) { return; }
		var p = m.progress || {}, h = '';
		if ( CFG.offline ) {
			el.innerHTML = '<span>Data read from AWS <b>' + esc( m.generated ) + '</b> · costs for <b>' + m.cost_ok + ' of ' + m.accounts + '</b> accounts · instances for ' + m.ec2_ok + '</span><span class="vh-cost-bar__spacer"></span><span class="vh-chip">Exported snapshot — not live</span>';
			return;
		}
		if ( m.has_data ) {
			h += '<span>Data from <b>' + esc( m.generated ) + '</b> (' + esc( m.generated_ago ) + ')</span>';
			h += '<span>Costs for <b>' + m.cost_ok + ' of ' + m.accounts + '</b> accounts · instances for ' + m.ec2_ok + '</span>';
		}
		h += '<span class="vh-cost-bar__spacer"></span>';
		if ( m.running ) {
			var w = p.total ? Math.round( 100 * ( p.done || 0 ) / p.total ) : 5;
			h += '<span class="vh-cost-progress" aria-live="polite"><span class="vh-cost-progress__bar"><i style="width:' + w + '%"></i></span>' + esc( p.stage || 'Working…' ) + '</span>';
		}
		if ( m.can_refresh && m.auto ) {
			h += '<label class="vh-muted" style="display:inline-flex;gap:6px;align-items:center">Auto-refresh <select data-auto aria-label="Auto-refresh cost data" style="background:var(--vh-surface);color:var(--vh-ink);border:1px solid var(--vh-line-strong);border-radius:8px;padding:5px 8px;font:inherit;font-size:12.5px">' + m.auto.options.map( function ( o ) { return '<option value="' + esc( o[ 0 ] ) + '"' + ( o[ 0 ] === m.auto.mode ? ' selected' : '' ) + '>' + esc( o[ 1 ] ) + '</option>'; } ).join( '' ) + '</select></label>';
		}
		if ( m.can_refresh ) {
			h += '<button type="button" class="vh-btn vh-btn--primary" data-refresh' + ( m.running ? ' disabled' : '' ) + '>' + ( m.running ? 'Refreshing…' : 'Refresh from AWS' ) + '</button>';
		}
		h += '<span class="vh-muted" data-bar-msg></span>';
		el.innerHTML = h;
		var sel = el.querySelector( '[data-auto]' );
		if ( sel ) {
			sel.addEventListener( 'change', function () {
				sel.disabled = true;
				api( '/settings', { method: 'POST', body: { auto: sel.value } } ).then( function ( r ) {
					DATA.meta.auto = r.auto; sel.disabled = false; alertBar( 'Saved.' );
				} ).catch( function ( e ) { sel.disabled = false; alertBar( e.message ); } );
			} );
		}
		var b = el.querySelector( '[data-refresh]' );
		if ( b ) { b.addEventListener( 'click', function () { b.disabled = true; refresh(); } ); }
	}

	function render() {
		var d = DATA, m = d.meta || {};
		var h = '<div class="vh-cost-bar" data-bar></div>';

		if ( m.last_attempt ) {
			h += '<div class="vh-cost-notice vh-cost-notice--' + ( m.last_attempt.status === 'partial' ? 'warn' : 'bad' ) + '"><b>The last refresh ' + ( m.last_attempt.status === 'partial' ? 'was incomplete' : esc( m.last_attempt.status ) ) + '</b> (' + esc( m.last_attempt.when ) + '): ' + esc( m.last_attempt.message ) + ( m.has_data ? ' The figures below are from the last complete read.' : '' ) + '</div>';
		}
		if ( ! m.has_data ) {
			h += '<div class="vh-cost-notice">No cost data yet. ' + ( m.can_refresh ? 'Press <b>Refresh from AWS</b> to read Cost Explorer, CloudWatch and the price list for every account your AWS SSO login can see. It takes about ten minutes and costs roughly $0.01 per account in Cost Explorer requests.' : 'Ask an administrator to run the first refresh.' ) + '</div>';
			root.innerHTML = h;
			renderBar();
			if ( m.running ) { watch(); }
			return;
		}
		if ( m.cost_ok < m.accounts || ( m.errors && m.errors.length ) ) {
			h += '<div class="vh-cost-notice vh-cost-notice--warn"><b>Incomplete read:</b> costs came back for ' + m.cost_ok + ' of ' + m.accounts + ' accounts. Totals below cover only those. <details><summary>' + ( m.errors || [] ).length + ' errors</summary><ul>' + ( m.errors || [] ).map( function ( e ) { return '<li>' + esc( e ) + '</li>'; } ).join( '' ) + '</ul></details></div>';
		}

		var t = d.totals, ctx = d.context || {}, sv = d.savings || {};
		var lm = d.meta.periods ? d.meta.periods.last_month : null;
		h += '<div class="vh-tiles">';
		h += tile( 'Last full month', money( t.last_month ), lm ? dayLabel( lm.start ) + ' – ' + dayLabel( lm.end ) + ' (end exclusive), all services incl. tax' : '' );
		h += tile( 'This month so far', money( t.mtd ), t.days_el + ' of ' + t.dim + ' days complete' );
		h += tile( 'Projected month end', t.projected == null ? '—' : money( t.projected ), t.projected == null ? 'Available from the 2nd of the month' : 'Straight-line from the days so far · ' + pct( t.projected, t.last_month ) + ' vs last month' );
		h += tile( 'EC2 compute, last month', money( ctx.ec2_covered + ctx.ec2_on_demand ), money( ctx.ec2_covered ) + ' covered by a Savings Plan / reservation, ' + money( ctx.ec2_on_demand ) + ' billed on demand' );
		h += '<a class="vh-tile vh-tile--good" href="' + esc( CFG.savingsUrl ) + '"><span class="vh-tile__label">Confirmed savings open</span><span class="vh-tile__value">' + money( sv.confirmed_open && sv.confirmed_open.saving ) + '<span class="vh-muted" style="font-size:13px;font-weight:500"> /month</span></span><span class="vh-tile__meta">' + ( sv.confirmed_open ? sv.confirmed_open.count : 0 ) + ' suggestions · ' + ( sv.verify_open ? sv.verify_open.count : 0 ) + ' more need confirmation · accepted plan ' + money( sv.accepted && sv.accepted.saving ) + '/month →</span></a>';
		h += '</div>';

		// Daily trend + spikes.
		h += '<div class="vh-cost-grid2">';
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>Daily spend, all accounts</h2><p class="vh-sub">Cost Explorer, last ' + d.daily.dates.length + ' complete days · hover a day for its biggest services</p><span class="vh-cost-bar__spacer"></span><button type="button" class="vh-btn" data-chart-toggle>' + ( state.chartTable ? 'Show chart' : 'Show as table' ) + '</button></div><div data-chart></div></section>';
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>Spikes</h2><p class="vh-sub">A service at 3× or more its own baseline and at least $50 on a day</p></div>' + spikes( d.anomalies ) + '</section>';
		h += '</div>';

		// Accounts.
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>Accounts</h2><p class="vh-sub">Click an account for its services</p></div>';
		h += '<div class="vh-cost-filter"><input type="search" placeholder="Search accounts or IDs" aria-label="Search accounts" data-acct-q value="' + esc( state.acctQ ) + '"><select data-acct-env aria-label="Environment"><option value="">All environments</option><option>Production</option><option>Non-production</option><option>Unclassified</option></select></div>';
		h += '<div class="vh-cost-scroll" data-accounts></div></section>';

		// Services + usage lines.
		h += '<div class="vh-cost-grid2">';
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>Services</h2><p class="vh-sub">All accounts</p></div><div class="vh-cost-scroll">' + services( d.services ) + '</div></section>';
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>Biggest cost lines, last month</h2><p class="vh-sub">Service · usage type · account</p></div><div class="vh-cost-scroll">' + lines( d.lines ) + '</div></section>';
		h += '</div>';

		// Schedules.
		h += '<section class="vh-cost-card"><div class="vh-cost-card__head"><h2>What starts and stops your instances</h2><p class="vh-sub">Scheduler set-up read from AWS, and what each instance actually did over the last 14 days (CloudWatch)</p></div><div data-sched></div></section>';

		root.innerHTML = h;
		renderBar();
		renderChart();
		renderAccounts();
		renderSchedules();
		wire();
		if ( m.running && ! CFG.offline ) { watch(); }
	}

	function tile( label, value, meta ) {
		return '<div class="vh-tile vh-tile--neutral"><span class="vh-tile__label">' + esc( label ) + '</span><span class="vh-tile__value">' + value + '</span><span class="vh-tile__meta">' + esc( meta ) + '</span></div>';
	}

	function wire() {
		var q = root.querySelector( '[data-acct-q]' ), e = root.querySelector( '[data-acct-env]' ), c = root.querySelector( '[data-chart-toggle]' );
		if ( q ) { q.addEventListener( 'input', function () { state.acctQ = q.value; renderAccounts(); } ); }
		if ( e ) { e.value = state.acctEnv; e.addEventListener( 'change', function () { state.acctEnv = e.value; renderAccounts(); } ); }
		if ( c ) { c.addEventListener( 'click', function () { state.chartTable = ! state.chartTable; c.textContent = state.chartTable ? 'Show chart' : 'Show as table'; renderChart(); } ); }
	}

	/* ------------------------------------------------------- daily chart */
	function renderChart() {
		var el = root.querySelector( '[data-chart]' ), dd = DATA.daily;
		if ( ! el ) { return; }
		if ( ! dd.dates.length ) { el.innerHTML = '<p class="vh-muted">No daily data.</p>'; return; }
		if ( state.chartTable ) {
			var t = '<div class="vh-cost-scroll" style="max-height:260px"><table class="vh-cost-table"><thead><tr><th>Day</th><th class="r">Total</th>' + dd.services.map( function ( s ) { return '<th class="r">' + esc( s.service ) + '</th>'; } ).join( '' ) + '</tr></thead><tbody>';
			dd.dates.forEach( function ( day, i ) { t += '<tr><td>' + dayLabel( day ) + '</td><td class="r">' + money( dd.total[ i ] ) + '</td>' + dd.services.map( function ( s ) { return '<td class="r">' + money( s.values[ i ] ) + '</td>'; } ).join( '' ) + '</tr>'; } );
			el.innerHTML = t + '</tbody></table></div>';
			return;
		}
		var W = 640, H = 220, L = 52, B = 22, T = 8, n = dd.dates.length;
		var max = Math.max.apply( null, dd.total ) || 1;
		var step = Math.pow( 10, Math.floor( Math.log10( max ) ) ), nice = Math.ceil( max / step ) * step;
		if ( nice / step > 6 ) { step *= 2; }
		var bw = ( W - L ) / n, s = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" role="img" aria-label="Daily AWS spend">';
		s += '<g class="grid">';
		for ( var v = 0; v <= nice; v += step ) {
			var y = T + ( H - B - T ) * ( 1 - v / nice );
			s += '<line x1="' + L + '" x2="' + W + '" y1="' + y + '" y2="' + y + '"></line><text x="' + ( L - 6 ) + '" y="' + ( y + 4 ) + '" text-anchor="end">' + money( v ) + '</text>';
		}
		s += '</g>';
		dd.total.forEach( function ( val, i ) {
			var bh = ( H - B - T ) * val / nice, x = L + i * bw + 1, y = H - B - bh, w = Math.max( 1, bw - 2 );
			var r = Math.min( 4, w / 2, bh );
			s += '<path class="bar" data-i="' + i + '" d="M' + x + ' ' + ( H - B ) + 'V' + ( y + r ) + 'Q' + x + ' ' + y + ' ' + ( x + r ) + ' ' + y + 'H' + ( x + w - r ) + 'Q' + ( x + w ) + ' ' + y + ' ' + ( x + w ) + ' ' + ( y + r ) + 'V' + ( H - B ) + 'Z"></path>';
			s += '<rect class="hit" data-i="' + i + '" x="' + ( L + i * bw ) + '" y="' + T + '" width="' + bw + '" height="' + ( H - B - T ) + '"></rect>';
			if ( i % Math.ceil( n / 8 ) === 0 ) { s += '<g class="axis"><text x="' + ( x + w / 2 ) + '" y="' + ( H - 6 ) + '" text-anchor="middle">' + dayLabel( dd.dates[ i ] ) + '</text></g>'; }
		} );
		s += '</svg><div class="vh-cost-tip" hidden></div>';
		// Monthly charges (tax, subscriptions, support) are booked on the 1st;
		// say so when that day towers over the rest, using the day's own figures.
		var sorted = dd.total.slice().sort( function ( a, b ) { return a - b; } ), med = sorted[ Math.floor( sorted.length / 2 ) ] || 0, notes = [];
		dd.dates.forEach( function ( day, i ) {
			if ( day.slice( 8 ) !== '01' || dd.total[ i ] < 3 * med ) { return; }
			var tax = dd.services.filter( function ( sv ) { return sv.service === 'Tax'; } )[ 0 ];
			notes.push( dayLabel( day ) + ' (' + money( dd.total[ i ] ) + ') is tall because AWS books monthly charges on the 1st' + ( tax && tax.values[ i ] > 0 ? ' — tax alone was ' + money( tax.values[ i ] ) + ' that day' : '' ) + '. It is not a spike.' );
		} );
		el.innerHTML = '<div class="vh-cost-chart">' + s + '</div>' + ( notes.length ? '<p class="vh-sub vh-muted" style="margin:8px 0 0;font-size:12px">' + notes.map( esc ).join( ' ' ) + '</p>' : '' );
		var tip = el.querySelector( '.vh-cost-tip' ), chart = el.querySelector( '.vh-cost-chart' );
		el.querySelectorAll( '.hit' ).forEach( function ( r ) {
			r.addEventListener( 'mousemove', function ( ev ) {
				var i = +r.getAttribute( 'data-i' ), rows = dd.services.map( function ( sv ) { return [ sv.service, sv.values[ i ] ]; } ).filter( function ( x ) { return x[ 1 ] > 0; } );
				var other = dd.total[ i ] - rows.reduce( function ( a, x ) { return a + x[ 1 ]; }, 0 );
				tip.innerHTML = '<b>' + dayLabel( dd.dates[ i ] ) + ' · ' + money( dd.total[ i ] ) + '</b><table>' + rows.map( function ( x ) { return '<tr><td>' + esc( x[ 0 ] ) + '</td><td>' + money( x[ 1 ] ) + '</td></tr>'; } ).join( '' ) + ( other > 0.5 ? '<tr><td>Everything else</td><td>' + money( other ) + '</td></tr>' : '' ) + '</table>';
				tip.hidden = false;
				var b = chart.getBoundingClientRect(), x = ev.clientX - b.left + 12;
				if ( x + 260 > b.width ) { x = ev.clientX - b.left - 272; }
				tip.style.left = Math.max( 0, x ) + 'px'; tip.style.top = '8px';
				el.querySelectorAll( '.bar' ).forEach( function ( p ) { p.classList.toggle( 'is-hover', p.getAttribute( 'data-i' ) === String( i ) ); } );
			} );
			r.addEventListener( 'mouseleave', function () { tip.hidden = true; el.querySelectorAll( '.bar.is-hover' ).forEach( function ( p ) { p.classList.remove( 'is-hover' ); } ); } );
		} );
	}

	/* ------------------------------------------------------------ spikes */
	function spikes( list ) {
		if ( ! list || ! list.length ) { return '<p class="vh-muted">No spikes in the last 45 days.</p>'; }
		return '<div class="vh-cost-scroll"><table class="vh-cost-table"><thead><tr><th>Account · service</th><th>When</th><th class="r">Spent</th><th class="r">Above normal</th></tr></thead><tbody>' + list.slice( 0, 12 ).map( function ( a ) {
			var why = ( a.usage || [] ).map( function ( u ) { return esc( u.usage_type ) + ' ' + money( u.cost ); } ).join( ' · ' );
			return '<tr><td>' + esc( a.account_name || a.account ) + '<span class="sub">' + esc( a.service ) + ( why ? ' — this month: ' + why : '' ) + '</span></td><td>' + dayLabel( a.start ) + ( a.end !== a.start ? ' – ' + dayLabel( a.end ) : '' ) + '<span class="sub">' + a.days + ' day' + ( a.days > 1 ? 's' : '' ) + ( a.ongoing ? ' · <b>still going</b>' : ' · ended' ) + '</span></td><td class="r">' + money( a.total ) + '<span class="sub">peak ' + money( a.peak ) + '/day</span></td><td class="r">' + money( a.excess ) + '<span class="sub">normal ' + money( a.baseline ) + '/day</span></td></tr>';
		} ).join( '' ) + '</tbody></table></div>';
	}

	/* ---------------------------------------------------------- accounts */
	function renderAccounts() {
		var el = root.querySelector( '[data-accounts]' );
		if ( ! el ) { return; }
		var q = state.acctQ.toLowerCase(), rows = DATA.accounts.filter( function ( a ) {
			return ( ! q || ( a.name + ' ' + a.id ).toLowerCase().indexOf( q ) >= 0 ) && ( ! state.acctEnv || a.env === state.acctEnv );
		} );
		rows.sort( function ( x, y ) {
			var k = state.acctSort, a = k === 'name' ? x.name : ( x[ k ] || 0 ), b = k === 'name' ? y.name : ( y[ k ] || 0 );
			return ( a > b ? 1 : a < b ? -1 : 0 ) * state.acctDir;
		} );
		var max = Math.max.apply( null, rows.map( function ( a ) { return a.last_month; } ).concat( [ 1 ] ) );
		var sums = rows.reduce( function ( s, a ) { s.lm += a.last_month; s.mtd += a.mtd; s.p += a.projected || 0; return s; }, { lm: 0, mtd: 0, p: 0 } );
		function th( k, label, r ) { var on = state.acctSort === k; return '<th class="' + ( r ? 'r' : '' ) + '" aria-sort="' + ( on ? ( state.acctDir > 0 ? 'ascending' : 'descending' ) : 'none' ) + '"><button type="button" data-sort="' + k + '">' + label + ( on ? ( state.acctDir > 0 ? ' ▲' : ' ▼' ) : '' ) + '</button></th>'; }
		var h = '<table class="vh-cost-table"><thead><tr>' + th( 'name', 'Account' ) + '<th>Environment</th>' + th( 'last_month', 'Last month', 1 ) + th( 'mtd', 'This month so far', 1 ) + th( 'projected', 'Projected', 1 ) + '<th class="r">vs last</th></tr></thead><tbody>';
		rows.forEach( function ( a ) {
			var p = a.projected;
			var ch = p == null || ! a.last_month ? '' : pct( p, a.last_month ), cls = p == null ? '' : ( p > a.last_month * 1.1 ? 'up' : ( p < a.last_month * 0.9 ? 'down' : '' ) );
			h += '<tr class="is-click" data-acct="' + esc( a.id ) + '" tabindex="0" aria-expanded="' + ( state.open[ a.id ] ? 'true' : 'false' ) + '"><td>' + esc( a.name || a.id ) + '<span class="sub">' + esc( a.id ) + '</span><span class="vh-cost-magn" style="width:' + Math.max( 0.5, 100 * a.last_month / max ).toFixed( 1 ) + '%"></span></td><td>' + esc( a.env ) + '</td><td class="r">' + money( a.last_month ) + '</td><td class="r">' + money( a.mtd ) + '</td><td class="r">' + money( p ) + '</td><td class="r ' + cls + '">' + ch + '</td></tr>';
			if ( state.open[ a.id ] ) { h += '<tr class="vh-cost-expand"><td colspan="6">' + acctServices( a ) + '</td></tr>'; }
		} );
		h += '</tbody><tfoot><tr><td><b>' + rows.length + ' accounts</b></td><td></td><td class="r"><b>' + money( sums.lm ) + '</b></td><td class="r"><b>' + money( sums.mtd ) + '</b></td><td class="r"><b>' + money( sums.p ) + '</b></td><td></td></tr></tfoot></table>';
		el.innerHTML = h;
		el.querySelectorAll( '[data-sort]' ).forEach( function ( b ) { b.addEventListener( 'click', function () { var k = b.getAttribute( 'data-sort' ); state.acctDir = state.acctSort === k ? -state.acctDir : ( k === 'name' ? 1 : -1 ); state.acctSort = k; renderAccounts(); } ); } );
		el.querySelectorAll( '[data-acct]' ).forEach( function ( tr ) {
			function tog() { var id = tr.getAttribute( 'data-acct' ); state.open[ id ] = ! state.open[ id ]; renderAccounts(); }
			tr.addEventListener( 'click', tog );
			tr.addEventListener( 'keydown', function ( e ) { if ( e.key === 'Enter' || e.key === ' ' ) { e.preventDefault(); tog(); } } );
		} );
	}
	function acctServices( a ) {
		var lm = ( a.services && a.services.last_month ) || {}, mt = ( a.services && a.services.mtd ) || {}, keys = Object.keys( Object.assign( {}, lm, mt ) );
		keys.sort( function ( x, y ) { return ( lm[ y ] || 0 ) - ( lm[ x ] || 0 ); } );
		keys = keys.filter( function ( k ) { return Math.abs( lm[ k ] || 0 ) >= 1 || Math.abs( mt[ k ] || 0 ) >= 1; } );
		return '<table class="vh-cost-table"><thead><tr><th>Service</th><th class="r">Last month</th><th class="r">This month so far</th></tr></thead><tbody>' + keys.map( function ( k ) { return '<tr><td>' + esc( k ) + '</td><td class="r">' + money( lm[ k ] ) + '</td><td class="r">' + money( mt[ k ] ) + '</td></tr>'; } ).join( '' ) + '</tbody></table>';
	}

	/* ---------------------------------------------------------- services */
	function services( list ) {
		var max = Math.max.apply( null, list.map( function ( s ) { return s.last_month; } ).concat( [ 1 ] ) );
		return '<table class="vh-cost-table"><thead><tr><th>Service</th><th class="r">Last month</th><th class="r">This month so far</th></tr></thead><tbody>' + list.filter( function ( s ) { return Math.abs( s.last_month ) >= 1 || Math.abs( s.mtd ) >= 1; } ).slice( 0, 30 ).map( function ( s ) {
			return '<tr><td>' + esc( s.service ) + '<span class="vh-cost-magn" style="width:' + Math.max( 0.5, 100 * Math.max( 0, s.last_month ) / max ).toFixed( 1 ) + '%"></span></td><td class="r">' + money( s.last_month ) + '</td><td class="r">' + money( s.mtd ) + '</td></tr>';
		} ).join( '' ) + '</tbody></table>';
	}
	function lines( list ) {
		return '<table class="vh-cost-table"><thead><tr><th>Usage</th><th class="r">Quantity</th><th class="r">Cost</th></tr></thead><tbody>' + list.slice( 0, 25 ).map( function ( l ) {
			return '<tr><td>' + esc( l.usage_type ) + '<span class="sub">' + esc( l.service ) + ' · ' + esc( l.account_name || l.account ) + '</span></td><td class="r">' + Number( l.qty ).toLocaleString() + '<span class="sub">' + esc( l.unit ) + '</span></td><td class="r">' + money( l.cost ) + '</td></tr>';
		} ).join( '' ) + '</tbody></table>';
	}

	/* --------------------------------------------------------- schedules */
	function renderSchedules() {
		var el = root.querySelector( '[data-sched]' ), s = DATA.schedules;
		if ( ! el || ! s ) { return; }
		var weeks = Math.max( 1, Math.round( ( s.possible.all || 336 ) / 168 ) ), h = '';
		var hubs = s.stacks.filter( function ( x ) { return x.role === 'hub'; } ), spokes = s.stacks.filter( function ( x ) { return x.role !== 'hub'; } );

		h += '<h3>Instance Scheduler</h3>';
		if ( ! s.stacks.length ) {
			h += '<p class="vh-muted">No Instance Scheduler stacks found in the accounts and regions read.</p>';
		} else {
			hubs.forEach( function ( x ) {
				var p = x.params || {};
				h += '<p><b>Hub</b> in ' + esc( x.account_name ) + ' (' + esc( x.region ) + '), stack <code>' + esc( x.stack ) + '</code>' + ( x.version ? ' v' + esc( x.version ) : '' ) + ' · ' + esc( x.status ) + '<br>Reads the <code>' + esc( p.TagName || '?' ) + '</code> tag · timezone ' + esc( p.DefaultTimezone || '?' ) + ' · runs every ' + esc( p.SchedulerFrequency || '?' ) + ' min · scheduling ' + ( p.SchedulingActive === 'Yes' ? 'active' : esc( p.SchedulingActive || '?' ) ) + ' · EC2 ' + esc( p.ScheduleEC2 || '?' ) + ', RDS ' + esc( p.ScheduleRds || '?' ) + '</p>';
			} );
			if ( spokes.length ) {
				var byVer = {};
				spokes.forEach( function ( x ) { var k = x.version || 'unknown'; ( byVer[ k ] = byVer[ k ] || [] ).push( x.account_name ); } );
				h += '<p class="vh-muted">Connected accounts: ' + Object.keys( byVer ).map( function ( v ) { return '<b>v' + esc( v ) + '</b> — ' + byVer[ v ].map( esc ).join( ', ' ); } ).join( '; ' ) + '</p>';
			}
			h += '<p class="vh-muted">The schedule definitions themselves live in the hub’s configuration table, which the read-only role cannot decrypt. What each instance actually did is below.</p>';
		}
		if ( s.fleet ) {
			h += '<div class="vh-cost-notice"><b>Measured schedule:</b> ' + s.fleet.count + ' scheduled instances ran a median of <b>' + s.fleet.hours_week + ' hours a week</b> — ' + esc( s.fleet.label ) + '. Tag values on schedule: ' + s.fleet.values.map( function ( v ) { return '<code>' + esc( v ) + '</code>'; } ).join( ', ' ) + '.</div>';
		}

		if ( s.rules.length || s.schedules.length ) {
			h += '<h3 style="margin-top:14px">Other start/stop schedules</h3><div class="vh-cost-scroll"><table class="vh-cost-table"><thead><tr><th>Account</th><th>Name</th><th>When</th><th>State</th><th>Target</th></tr></thead><tbody>';
			s.rules.forEach( function ( r ) { h += '<tr><td>' + esc( r.account_name ) + '</td><td>' + esc( r.name ) + '<span class="sub">' + esc( r.description ) + '</span></td><td><code>' + esc( r.expression ) + '</code><span class="sub">EventBridge rule · UTC</span></td><td>' + esc( r.state ) + '</td><td>' + r.targets.map( function ( t ) { return esc( t.split( ':' ).slice( -1 )[ 0 ] ); } ).join( '<br>' ) + '</td></tr>'; } );
			s.schedules.forEach( function ( r ) { h += '<tr><td>' + esc( r.account_name ) + '</td><td>' + esc( r.name ) + '</td><td><code>' + esc( r.expression ) + '</code><span class="sub">EventBridge Scheduler · ' + esc( r.timezone || 'UTC' ) + '</span></td><td>' + esc( r.state ) + '</td><td>' + esc( ( r.target || '' ).split( ':' ).slice( -1 )[ 0 ] ) + '</td></tr>'; } );
			h += '</tbody></table></div>';
		}

		var accts = Array.from( new Set( s.instances.map( function ( i ) { return i.account_name; } ) ) ).sort();
		h += '<h3 style="margin-top:14px">Scheduled and non-production instances</h3>';
		h += '<div class="vh-cost-filter"><select data-sched-acct aria-label="Account"><option value="">All accounts (' + s.instances.length + ')</option>' + accts.map( function ( a ) { return '<option' + ( state.schedAcct === a ? ' selected' : '' ) + '>' + esc( a ) + '</option>'; } ).join( '' ) + '</select></div>';
		h += '<div class="vh-cost-scroll"><table class="vh-cost-table"><thead><tr><th>Instance</th><th><code>' + esc( s.tag ) + '</code> tag</th><th>Last scheduler action</th><th>What it did (14 days)</th><th>Hours by weekday and hour (' + esc( DATA.meta.timezone ) + ')</th></tr></thead><tbody>';
		s.instances.filter( function ( i ) { return ! state.schedAcct || i.account_name === state.schedAcct; } ).forEach( function ( i ) {
			h += '<tr><td>' + esc( i.name || i.id ) + '<span class="sub">' + esc( i.id ) + ' · ' + esc( i.type ) + ' · ' + esc( i.state ) + '</span><span class="sub">' + esc( i.account_name ) + '</span></td><td>' + ( i.tag ? '<code>' + esc( i.tag ) + '</code>' : '—' ) + ( i.legacy ? '<span class="sub">also ' + esc( i.legacy ) + '</span>' : '' ) + '</td><td>' + esc( i.last_action || '—' ) + '</td><td>' + esc( i.pattern ) + '<span class="sub">' + i.hours + ' of ' + s.possible.all + ' h · ' + i.weekend + ' of ' + s.possible.weekend + ' weekend h</span></td><td>' + weekGrid( i.grid, weeks ) + '</td></tr>';
		} );
		h += '</tbody></table></div>' + weekLegend( weeks );
		el.innerHTML = h;
		var sel = el.querySelector( '[data-sched-acct]' );
		if ( sel ) { sel.addEventListener( 'change', function () { state.schedAcct = sel.value; renderSchedules(); } ); }
	}

	load();
}() );

