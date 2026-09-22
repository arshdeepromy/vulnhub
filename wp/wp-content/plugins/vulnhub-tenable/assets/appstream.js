( function () {
	'use strict';
	var CFG = window.VH_APPSTREAM || {};
	var root = document.querySelector( '[data-vh-appstream]' );
	if ( ! root ) { return; }

	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"]/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ c ]; } ); }
	function when( s ) { return s ? esc( String( s ).replace( 'T', ' ' ).slice( 0, 19 ) ) : '—'; }

	function fetchSummary() {
		root.innerHTML = '<div class="vh-panel"><p>Loading…</p></div>';
		wp.apiFetch( { url: CFG.rest, headers: { 'X-WP-Nonce': CFG.nonce } } ).then( render ).catch( function () {
			root.innerHTML = '<div class="vh-panel"><p>Could not load AppStream data.</p></div>';
		} );
	}

	function render( s ) {
		s = s || {};
		if ( ! s.total ) {
			root.innerHTML = '<div class="vh-panel"><p>No AppStream streaming instances detected in the current inventory.</p></div>';
			return;
		}
		var keep = s.keep || null, red = s.redundant || [];

		var head = '<div class="vh-as-stats">'
			+ stat( s.total, 'AppStream assets' )
			+ stat( s.deletable_count, 'deletable in Tenable', 'warn' )
			+ stat( s.stale_count, 'stale &gt; 7 days' )
			+ '<code class="vh-as-re" title="Detection signature">' + esc( s.regex ) + '</code>'
			+ '</div>';

		var keepHtml = keep
			? '<div class="vh-as-keep"><span class="vh-as-keep__tag">KEEP · most recent</span>'
				+ '<div class="vh-as-keep__row"><b>' + esc( keep.hostname ) + '</b>'
				+ ( keep.deletable ? '<span class="vh-b vh-b--ok">mapped to Tenable</span>' : '<span class="vh-b vh-b--off">no Tenable record</span>' ) + '</div>'
				+ '<div class="vh-as-keep__meta">last seen ' + when( keep.last ) + ( keep.instance ? ' · ' + esc( keep.instance ) : '' ) + ( keep.region ? ' · ' + esc( keep.region ) : '' ) + '</div></div>'
			: '';

		var bulk = ( CFG.manage && s.deletable_count > 0 )
			? '<button type="button" class="vh-btn vh-btn--danger" data-vh-as-bulk>Delete all ' + s.deletable_count + ' redundant in Tenable</button>'
			: '';

		var rows = red.map( function ( n ) {
			var act = ! n.deletable
				? '<span class="vh-muted">no Tenable UUID</span>'
				: ( CFG.manage ? '<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-as-del="' + n.id + '">Delete</button>' : '<span class="vh-muted">read-only</span>' );
			return '<tr' + ( n.stale ? ' class="is-stale"' : '' ) + ' data-row="' + n.id + '">'
				+ '<td><code>' + esc( n.hostname ) + '</code></td>'
				+ '<td>' + when( n.last ) + '</td>'
				+ '<td>' + esc( n.source || '—' ) + '</td>'
				+ '<td>' + ( n.stale ? '<span class="vh-b vh-b--off">stale</span>' : '<span class="vh-b vh-b--live">recent</span>' ) + '</td>'
				+ '<td class="vh-as-act">' + act + '</td></tr>';
		} ).join( '' );

		root.innerHTML = head + keepHtml
			+ '<div class="vh-as-barrow">' + bulk + '<span class="vh-as-status" data-vh-as-status role="status"></span></div>'
			+ '<table class="vh-as-table"><thead><tr><th>Computer name</th><th>Last seen</th><th>Source</th><th>State</th><th></th></tr></thead><tbody>'
			+ ( rows || '<tr><td colspan="5" class="vh-muted">Only the most-recent instance remains — nothing redundant.</td></tr>' )
			+ '</tbody></table>';
	}

	function stat( n, label, tone ) {
		return '<div class="vh-as-stat' + ( tone ? ' vh-as-stat--' + tone : '' ) + '"><span class="vh-as-stat__n">' + esc( n ) + '</span><span class="vh-as-stat__l">' + label + '</span></div>';
	}

	function setStatus( msg ) { var el = root.querySelector( '[data-vh-as-status]' ); if ( el ) { el.textContent = msg; } }

	function del( ids ) {
		setStatus( 'Deleting…' );
		wp.apiFetch( { url: CFG.del, method: 'POST', headers: { 'X-WP-Nonce': CFG.nonce }, data: { ids: ids } } )
			.then( function ( r ) {
				var msg = r.deleted + ' deleted';
				if ( r.gone ) { msg += ', ' + r.gone + ' already gone from Tenable'; }
				if ( r.failed && r.failed.length ) { msg += ', ' + r.failed.length + ' failed — ' + r.failed[0].message; }
				render( r.summary || {} );
				setStatus( msg );
			} )
			.catch( function ( e ) { setStatus( ( e && e.message ) || 'Delete failed.' ); } );
	}

	root.addEventListener( 'click', function ( e ) {
		var one = e.target.closest ? e.target.closest( '[data-vh-as-del]' ) : null;
		if ( one ) {
			var id = parseInt( one.getAttribute( 'data-vh-as-del' ), 10 );
			var host = ( one.closest( 'tr' ).querySelector( 'code' ) || {} ).textContent || 'this asset';
			if ( window.confirm( 'Delete ' + host + ' from Tenable? This calls the Tenable API and cannot be undone.' ) ) { del( [ id ] ); }
			return;
		}
		var bulk = e.target.closest ? e.target.closest( '[data-vh-as-bulk]' ) : null;
		if ( bulk ) {
			var ids = Array.prototype.map.call( root.querySelectorAll( '[data-vh-as-del]' ), function ( b ) { return parseInt( b.getAttribute( 'data-vh-as-del' ), 10 ); } );
			if ( ids.length && window.confirm( 'Delete all ' + ids.length + ' redundant AppStream assets from Tenable? This calls the Tenable API and cannot be undone.' ) ) { del( ids ); }
		}
	} );

	fetchSummary();
}() );
