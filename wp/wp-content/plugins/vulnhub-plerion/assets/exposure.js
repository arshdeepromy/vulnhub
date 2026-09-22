( function () {
	'use strict';
	var DATA = window.VH_PLERION_EXPOSURE || { accounts: {} };
	var sel  = document.querySelector( '[data-vh-exp-account]' );
	var map  = document.querySelector( '[data-vh-exp-map]' );
	var meta = document.querySelector( '[data-vh-exp-meta]' );
	if ( ! sel || ! map ) { return; }

	var accounts = Object.keys( DATA.accounts || {} ).sort( function ( a, b ) {
		return ( DATA.accounts[ b ].exposed || [] ).length - ( DATA.accounts[ a ].exposed || [] ).length;
	} );

	if ( ! accounts.length ) {
		map.innerHTML = '<div class="vh-panel"><p>No exposure snapshot yet. Run the Plerion connector to populate it.</p></div>';
		return;
	}

	accounts.forEach( function ( a ) {
		var o = document.createElement( 'option' );
		o.value = a;
		o.textContent = a + ' (' + ( DATA.accounts[ a ].exposed || [] ).length + ' exposed)';
		sel.appendChild( o );
	} );

	function riskClass( r ) { return r >= 7 ? 'crit' : ( r >= 4 ? 'warn' : 'ok' ); }
	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"]/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ c ]; } ); }
	function cut( s, n ) { s = String( s || '' ); return s.length > n ? s.slice( 0, n - 1 ) + '…' : s; }

	function draw( acct ) {
		var d  = DATA.accounts[ acct ] || { exposed: [], internal: 0 };
		var ex = d.exposed || [];
		if ( ! ex.length ) { map.innerHTML = '<div class="vh-panel"><p>No publicly-exposed assets in this account.</p></div>'; if ( meta ) { meta.textContent = '0 internet-facing'; } return; }

		var NW = 280, NH = 30, GAP = 16, TOP = 96;
		var W = 1000, H = TOP + ex.length * ( NH + GAP ) + 90;
		var netX = 78, midX = 360, midR = midX + NW, intX = 848, cy = H / 2;

		var s = '<svg viewBox="0 0 ' + W + ' ' + H + '" class="vh-exp-svg" preserveAspectRatio="xMidYMin meet">';

		// edges
		ex.forEach( function ( a, i ) {
			var y = TOP + i * ( NH + GAP ) + NH / 2;
			s += '<path class="vh-exp-edge vh-exp-edge--in" d="M' + ( netX + 30 ) + ',' + cy + ' C' + ( ( netX + midX ) / 2 ) + ',' + cy + ' ' + ( midX - 70 ) + ',' + y + ' ' + midX + ',' + y + '"/>';
			s += '<path class="vh-exp-edge vh-exp-edge--out" d="M' + midR + ',' + y + ' C' + ( midR + 70 ) + ',' + y + ' ' + ( intX - 70 ) + ',' + cy + ' ' + ( intX - 34 ) + ',' + cy + '"/>';
		} );

		// internet
		s += '<g class="vh-exp-net"><circle cx="' + netX + '" cy="' + cy + '" r="30"/><circle class="vh-exp-pulse" cx="' + netX + '" cy="' + cy + '" r="30"/>';
		s += '<text x="' + netX + '" y="' + ( cy + 5 ) + '" text-anchor="middle" font-size="18">🌐</text>';
		s += '<text class="vh-exp-cap" x="' + netX + '" y="' + ( cy - 40 ) + '" text-anchor="middle">Internet</text></g>';

		// internal
		s += '<g class="vh-exp-internal"><rect x="' + ( intX - 34 ) + '" y="' + ( cy - 30 ) + '" rx="10" width="150" height="60"/>';
		s += '<text x="' + ( intX + 41 ) + '" y="' + ( cy - 4 ) + '" text-anchor="middle">Internal estate</text>';
		s += '<text class="vh-exp-cap" x="' + ( intX + 41 ) + '" y="' + ( cy + 16 ) + '" text-anchor="middle">' + d.internal + ' imported</text></g>';

		// header captions
		s += '<text class="vh-exp-col" x="' + ( midX + NW / 2 ) + '" y="' + ( TOP - 40 ) + '" text-anchor="middle">In front of the internet (' + ex.length + ')</text>';

		// exposed nodes
		ex.forEach( function ( a, i ) {
			var y  = TOP + i * ( NH + GAP );
			var yc = y + NH / 2;
			s += '<g class="vh-exp-node vh-exp-node--' + riskClass( a.risk ) + '">';
			s += '<rect x="' + midX + '" y="' + y + '" rx="8" width="' + NW + '" height="' + NH + '"/>';
			s += '<text x="' + ( midX + 12 ) + '" y="' + ( yc + 4 ) + '">' + esc( cut( a.name, 30 ) ) + '</text>';
			s += '<text class="vh-exp-tag" x="' + ( midR - 10 ) + '" y="' + ( yc + 4 ) + '" text-anchor="end">' + esc( cut( ( a.type || '' ).replace( 'AWS::', '' ).split( '::' )[ 0 ], 14 ) ) + '</text>';
			s += '<title>' + esc( a.name ) + '\n' + esc( a.type ) + '  ·  ' + esc( a.region ) + '  ·  risk ' + ( a.risk || 0 ) + '</title>';
			s += '</g>';
		} );

		s += '</svg>';
		map.innerHTML = s;
		if ( meta ) { meta.textContent = ex.length + ' internet-facing · ' + d.internal + ' imported internal' + ( DATA.generated_at ? ' · ' + DATA.generated_at.slice( 0, 10 ) : '' ); }
	}

	sel.addEventListener( 'change', function () { draw( sel.value ); } );
	sel.value = accounts[ 0 ];
	draw( accounts[ 0 ] );
}() );
