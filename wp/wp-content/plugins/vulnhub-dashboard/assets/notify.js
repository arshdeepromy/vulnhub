( function () {
	'use strict';
	var CFG = window.VulnHubNotify || {};
	var wrap = document.querySelector( '[data-vh-bell]' );
	if ( ! wrap || ! CFG.rest ) { return; }
	var btn   = wrap.querySelector( '[data-vh-bell-toggle]' );
	var dot   = wrap.querySelector( '[data-vh-bell-count]' );
	var menu  = wrap.querySelector( '[data-vh-bell-menu]' );

	// The topbar is a left rail; lift the bell out to the page so it can float
	// at the very top-right of the screen.
	try { document.body.appendChild( wrap ); } catch ( e ) {}

	function esc( s ) { return String( s == null ? '' : s ).replace( /[&<>"]/g, function ( c ) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ c ]; } ); }

	function render( items ) {
		items = items || [];
		var total = items.reduce( function ( a, it ) { return a + ( parseInt( it.count, 10 ) || 0 ); }, 0 );
		if ( items.length ) {
			dot.textContent = total > 99 ? '99+' : ( total || items.length );
			dot.hidden = false;
			wrap.classList.add( 'has-unread' );
		} else {
			dot.hidden = true;
			wrap.classList.remove( 'has-unread' );
		}
		if ( ! items.length ) {
			menu.innerHTML = '<div class="vh-bell__empty">Nothing needs attention.</div>';
			return;
		}
		menu.innerHTML = '<div class="vh-bell__h">Notifications</div>' + items.map( function ( it ) {
			var inner = '<div class="vh-bell__item vh-bell__item--' + esc( it.severity || 'info' ) + '">'
				+ '<div class="vh-bell__t">' + esc( it.title ) + ( it.count ? ' <span class="vh-bell__n">' + esc( it.count ) + '</span>' : '' ) + '</div>'
				+ '<div class="vh-bell__b">' + esc( it.body ) + '</div></div>';
			return it.url ? '<a class="vh-bell__link" href="' + esc( it.url ) + '">' + inner + '</a>' : inner;
		} ).join( '' );
	}

	function load() {
		var opts = { url: CFG.rest, headers: { 'X-WP-Nonce': CFG.nonce } };
		var req = ( window.wp && wp.apiFetch ) ? wp.apiFetch( opts ) : fetch( CFG.rest, { headers: opts.headers } ).then( function ( r ) { return r.json(); } );
		req.then( function ( d ) { render( ( d && d.items ) || [] ); } ).catch( function () {} );
	}

	function place() {
		// The topbar is a vertical rail, so the bell can sit low and left. Anchor
		// the fixed menu to the button's actual position and open it toward the
		// larger empty side.
		var r = btn.getBoundingClientRect();
		var up = r.top > window.innerHeight / 2;
		var left = r.left < window.innerWidth / 2;
		menu.style.top = up ? 'auto' : ( r.bottom + 8 ) + 'px';
		menu.style.bottom = up ? ( window.innerHeight - r.top + 8 ) + 'px' : 'auto';
		menu.style.left = left ? Math.max( 8, r.left ) + 'px' : 'auto';
		menu.style.right = left ? 'auto' : Math.max( 8, window.innerWidth - r.right ) + 'px';
	}

	function open( state ) {
		var show = state == null ? menu.hidden : state;
		if ( show ) { place(); }
		menu.hidden = ! show;
		btn.setAttribute( 'aria-expanded', show ? 'true' : 'false' );
		wrap.classList.toggle( 'is-open', show );
	}

	btn.addEventListener( 'click', function ( e ) { e.stopPropagation(); open(); } );
	document.addEventListener( 'click', function ( e ) { if ( ! wrap.contains( e.target ) ) { open( false ); } } );
	document.addEventListener( 'keydown', function ( e ) { if ( e.key === 'Escape' ) { open( false ); } } );

	load();
	setInterval( load, 120000 ); // refresh every 2 minutes so a fresh sync surfaces on its own
}() );
