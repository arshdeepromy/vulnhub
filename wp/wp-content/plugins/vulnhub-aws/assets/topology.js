/*
 * Cloud Network — the whole-estate flowchart.
 *
 * Four bands stacked top to bottom, and a lane per route out of the estate.
 * The bands are ordinary flow layout; only the connectors are SVG, drawn into
 * one overlay from measured card positions. That is deliberate: laying the
 * cards out in SVG would mean re-implementing text wrapping, and laying the
 * connectors out in HTML would mean elbows made of borders. Each does the half
 * it is good at.
 *
 * The overlay is redrawn on resize and whenever a card opens, because both
 * move the boxes the lines are tied to.
 */
( function () {
	'use strict';

	var cfg  = window.VH_AWS_TOPOLOGY || {};
	var host = document.querySelector( '[data-vh-estate]' );

	if ( ! host || ! cfg.rest ) {
		return;
	}

	var ICONS = {
		internet: 'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z',
		onprem:   'M4 20V9l8-5 8 5v11M9 20v-6h6v6',
		firewall: 'M12 3l7 3v5c0 4.4-2.9 8.3-7 10-4.1-1.7-7-5.6-7-10V6l7-3z',
		tgw:      'M12 5v14M5 12h14M8 8l8 8M16 8l-8 8',
		igw:      'M4 12h16M14 6l6 6-6 6',
		nat:      'M20 12H4M10 6l-6 6 6 6',
		vpc:      'M3 6h18v12H3zM7 10h10v4H7z',
	};

	function el( tag, cls, text ) {
		var n = document.createElement( tag );
		if ( cls ) { n.className = cls; }
		if ( null != text ) { n.textContent = String( text ); }
		return n;
	}

	/*
	 * A medallion rather than a bare glyph: a ringed disc reads as a node on a
	 * diagram, where a 17px line icon reads as a bullet point. The ring also
	 * gives risk somewhere to live -- a lane that admits every port, or one
	 * with public addresses on it, pulses red instead of needing a sentence.
	 */
	function medallion( kind, risk ) {
		var m = el( 'span', 'vh-estate-med vh-estate-med--' + ( kind || 'vpc' ) + ( risk ? ' is-risk' : '' ) );
		m.appendChild( icon( kind ) );
		if ( risk ) { m.appendChild( el( 'span', 'vh-estate-med__pulse' ) ); }
		return m;
	}

	function icon( kind ) {
		var ns  = 'http://www.w3.org/2000/svg';
		var svg = document.createElementNS( ns, 'svg' );
		svg.setAttribute( 'viewBox', '0 0 24 24' );
		svg.setAttribute( 'aria-hidden', 'true' );
		svg.setAttribute( 'class', 'vh-estate-icon vh-estate-icon--' + ( kind || 'vpc' ) );
		var p = document.createElementNS( ns, 'path' );
		p.setAttribute( 'd', ICONS[ kind ] || ICONS.vpc );
		p.setAttribute( 'fill', 'none' );
		p.setAttribute( 'stroke', 'currentColor' );
		p.setAttribute( 'stroke-width', '1.7' );
		p.setAttribute( 'stroke-linecap', 'round' );
		p.setAttribute( 'stroke-linejoin', 'round' );
		svg.appendChild( p );
		return svg;
	}

	/* ---------------------------------------------------------------- cards */

	function destCard( node ) {
		var c = el( 'div', 'vh-estate-card vh-estate-card--dest vh-estate-card--' + node.kind );
		c.id = 'n-' + node.id;
		c.appendChild( medallion( node.kind, false ) );
		c.appendChild( el( 'span', 'vh-estate-name', node.label ) );
		return c;
	}

	function midCard( node, redraw ) {
		var c = el( 'div', 'vh-estate-card vh-estate-card--mid vh-estate-card--' + node.kind );
		c.id = 'n-' + node.id;

		var head = el( 'div', 'vh-estate-head' );
		head.appendChild( medallion( node.kind, !! node.risk ) );
		head.appendChild( el( 'span', 'vh-estate-name', node.label ) );
		c.appendChild( head );

		( node.meta || [] ).forEach( function ( m ) {
			if ( ! m || ! m.v ) { return; }
			var row = el( 'div', 'vh-estate-meta' );
			row.appendChild( el( 'span', 'vh-estate-meta__k', m.k ) );
			row.appendChild( el( 'span', 'vh-estate-meta__v', m.v ) );
			c.appendChild( row );
		} );

		if ( node.note ) {
			var d = disclosure( 'Why this lane exists', 'vh-estate-why' );
			d.body.appendChild( el( 'p', null, node.note ) );
			if ( redraw ) { d.details.addEventListener( 'toggle', redraw ); }
			c.appendChild( d.root );
		}

		return c;
	}

	/*
	 * A disclosure styled as a control.
	 *
	 * The first version used a bare <summary> with muted text, and it read as
	 * a caption rather than a button -- people tried to select it instead of
	 * clicking it. It is the same <details> underneath, so keyboard and
	 * screen-reader behaviour are unchanged; it just looks like the thing it
	 * has always been.
	 */
	function disclosure( label, cls ) {
		var d = el( 'details', 'vh-estate-disc ' + ( cls || '' ) );
		var s = el( 'summary', 'vh-estate-disc__btn' );
		s.appendChild( el( 'span', 'vh-estate-disc__caret', '\u25b8' ) );
		s.appendChild( el( 'span', null, label ) );
		d.appendChild( s );

		var body = el( 'div', 'vh-estate-disc__body' );
		d.appendChild( body );

		return { root: d, body: body, details: d };
	}

	function workCard( node, redraw ) {
		var c = el( 'div', 'vh-estate-card vh-estate-card--work' );
		c.id = 'n-' + node.id;

		var risky = ( node.ports || [] ).indexOf( 'all' ) !== -1 || !! node.public;
		var head  = el( 'div', 'vh-estate-head' );
		head.appendChild( medallion( 'vpc', risky ) );
		head.appendChild( el( 'span', 'vh-estate-name', node.label ) );
		c.appendChild( head );

		var nums = el( 'div', 'vh-estate-nums' );
		nums.appendChild( el( 'span', null, ( node.servers || 0 ).toLocaleString() + ' servers' ) );
		// Appliances are counted apart: an instance forwarding traffic for
		// other hosts is a device in the path, not part of the fleet.
		if ( node.devices ) {
			nums.appendChild( el( 'span', 'vh-estate-dev', node.devices + ' network device' + ( 1 === node.devices ? '' : 's' ) ) );
		}
		if ( node.public ) {
			nums.appendChild( el( 'span', 'vh-estate-pub', node.public + ' with a public address' ) );
		}
		c.appendChild( nums );

		function chips( label, list, cls ) {
			if ( ! ( list || [] ).length ) { return; }
			var pr = el( 'div', 'vh-estate-ports' );
			pr.appendChild( el( 'span', 'vh-estate-portlbl', label ) );
			list.slice( 0, 8 ).forEach( function ( x ) {
				pr.appendChild( el( 'span', 'vh-estate-port ' + cls + ( 'all' === x ? ' vh-estate-port--all' : '' ), 'all' === x ? 'ALL PORTS' : x ) );
			} );
			if ( list.length > 8 ) { pr.appendChild( el( 'span', 'vh-estate-port vh-estate-port--more', '+' + ( list.length - 8 ) ) ); }
			c.appendChild( pr );
		}

		chips( 'in', node.ports, 'vh-estate-port--in' );
		chips( 'out', node.ports_out, 'vh-estate-port--out' );

		if ( ( node.vpcs || [] ).length ) {
			var d = disclosure( 'List the ' + node.vpcs.length + ' VPCs', 'vh-estate-list' );

			var ul = el( 'ul' );
			node.vpcs.forEach( function ( v ) {
				var li = el( 'li' );
				li.appendChild( el( 'span', 'vh-estate-vpc', v.label ) );
				li.appendChild( el( 'code', null, v.sub ) );
				li.appendChild( el( 'span', 'vh-estate-acct', v.account ) );
				if ( v.servers ) { li.appendChild( el( 'span', 'vh-estate-srv', v.servers + ( v.public ? ' · ' + v.public + ' public' : '' ) ) ); }
				ul.appendChild( li );
			} );
			d.body.appendChild( ul );
			d.details.addEventListener( 'toggle', redraw );
			c.appendChild( d.root );
		}

		if ( ( node.entries || [] ).length ) {
			var e = disclosure( node.entries_total + ' public entry point' + ( 1 === node.entries_total ? '' : 's' ), 'vh-estate-list vh-estate-list--ips' );

			/*
			 * Grouped, servers first. A list that interleaves a NAT gateway
			 * with a database server reads as one inventory of comparable
			 * things, and they are not comparable: one is a box somebody
			 * patches, the other is plumbing.
			 */
			var order = { server: 0, network: 1, desktop: 2 };
			var names = { server: 'Servers', network: 'Network devices', desktop: 'Virtual desktops' };

			/*
			 * `order[x] || 9` would read the valid rank 0 as missing and sort
			 * servers last -- the same falsy-zero trap docs/FILTERS.md records
			 * for patch_available=0. Rank explicitly.
			 */
			var rank = function ( cls ) {
				return undefined === order[ cls ] ? 9 : order[ cls ];
			};
			var sorted = node.entries.slice().sort( function ( a, b ) {
				return rank( a.class ) - rank( b.class ) || a.ip.localeCompare( b.ip );
			} );

			var ips = el( 'ul', 'vh-estate-ips' );
			var head = '';

			sorted.forEach( function ( x ) {
				if ( x.class !== head ) {
					head = x.class;
					var h = el( 'li', 'vh-estate-group' );
					h.appendChild( el( 'span', null, names[ x.class ] || 'Other' ) );
					h.appendChild( el( 'span', 'vh-estate-groupn', String( sorted.filter( function ( y ) { return y.class === x.class; } ).length ) ) );
					ips.appendChild( h );
				}
				var li = el( 'li' );
				li.appendChild( el( 'code', 'vh-estate-ip', x.ip ) );

				/*
				 * The owner, not just the kind. "interface" answers nothing;
				 * the name of the balancer, the NAT gateway or the server is
				 * what somebody goes and looks at.
				 */
				if ( x.owner ) { li.appendChild( el( 'span', 'vh-estate-owner', x.owner ) ); }
				li.appendChild( el( 'span', 'vh-estate-kind', x.what ) );

				// A server can be followed all the way to its asset record.
				if ( x.asset ) {
					var a = el( 'a', 'vh-estate-go', ( x.host || 'asset' ) + ' \u2192' );
					a.href = '/assets/?asset=' + x.asset;
					a.title = 'Open this asset in the register';
					li.appendChild( a );
				}

				if ( x.sev && ( x.sev.c || x.sev.h ) ) {
					var s = el( 'span', 'vh-estate-sev' );
					if ( x.sev.c ) { s.appendChild( el( 'span', 'vh-estate-sevpill vh-estate-sevpill--c', x.sev.c + 'C' ) ); }
					if ( x.sev.h ) { s.appendChild( el( 'span', 'vh-estate-sevpill vh-estate-sevpill--h', x.sev.h + 'H' ) ); }
					li.appendChild( s );
				}

				ips.appendChild( li );
			} );

			if ( node.entries_total > node.entries.length ) {
				ips.appendChild( el( 'li', 'vh-estate-acct', '+ ' + ( node.entries_total - node.entries.length ) + ' more' ) );
			}
			e.body.appendChild( ips );
			e.details.addEventListener( 'toggle', redraw );
			c.appendChild( e.root );
		}

		return c;
	}

	/* --------------------------------------------------------------- hover */

	/*
	 * One tooltip, reused. It shows what the card had to abbreviate -- full
	 * appliance names, the whole port list, every account -- so the card can
	 * stay small without the detail being lost. Bound to focus as well as
	 * hover, or it is information only a mouse can reach.
	 */
	var tip = null;

	function tipFor( node ) {
		var box = el( 'div', 'vh-estate-tip__in' );
		box.appendChild( el( 'strong', null, node.label ) );

		if ( node.note ) { box.appendChild( el( 'p', null, node.note ) ); }

		( node.meta || [] ).forEach( function ( m ) {
			if ( ! m || ! m.v ) { return; }
			var r = el( 'div', 'vh-estate-tip__row' );
			r.appendChild( el( 'span', 'vh-estate-tip__k', m.k ) );
			r.appendChild( el( 'span', null, m.v ) );
			box.appendChild( r );
		} );

		var pair = function ( k, v ) {
			if ( ! v ) { return; }
			var r = el( 'div', 'vh-estate-tip__row' );
			r.appendChild( el( 'span', 'vh-estate-tip__k', k ) );
			r.appendChild( el( 'span', null, v ) );
			box.appendChild( r );
		};

		pair( 'Servers', node.servers ? node.servers.toLocaleString() : '' );
		pair( 'Network devices', node.devices ? node.devices + ' inline firewall appliance' + ( 1 === node.devices ? '' : 's' ) : '' );
		pair( 'Public', node.public ? node.public + ' with a public address' : '' );
		pair( 'Inbound', ( node.ports || [] ).length ? node.ports.join( ', ' ) : '' );
		pair( 'Outbound', ( node.ports_out || [] ).length ? node.ports_out.join( ', ' ) : '' );
		pair( 'Entry points', node.entries_total ? node.entries_total + ' public address' + ( 1 === node.entries_total ? '' : 'es' ) : '' );
		pair( 'Accounts', node.accounts ? String( node.accounts ) : '' );

		if ( ( node.vpcs || [] ).length ) {
			pair( 'Largest', node.vpcs.slice( 0, 3 ).map( function ( v ) { return v.label + ( v.servers ? ' (' + v.servers + ')' : '' ); } ).join( ', ' ) );
		}

		return box;
	}

	function bindTip( card, node ) {
		var show = function () {
			if ( ! tip ) { tip = el( 'div', 'vh-estate-tip' ); document.body.appendChild( tip ); }
			tip.innerHTML = '';
			tip.appendChild( tipFor( node ) );
			tip.classList.add( 'is-on' );

			var r = card.getBoundingClientRect();
			var w = tip.offsetWidth;
			// Kept inside the viewport: a tooltip that runs off the edge is
			// the same as no tooltip.
			var x = Math.min( Math.max( 10, r.left + r.width / 2 - w / 2 ), window.innerWidth - w - 10 );
			var y = r.top - tip.offsetHeight - 10;
			if ( y < 8 ) { y = r.bottom + 10; }
			tip.style.left = ( x + window.scrollX ) + 'px';
			tip.style.top  = ( y + window.scrollY ) + 'px';
		};
		var hide = function () { if ( tip ) { tip.classList.remove( 'is-on' ); } };

		card.addEventListener( 'mouseenter', show );
		card.addEventListener( 'mouseleave', hide );
		card.addEventListener( 'focusin', show );
		card.addEventListener( 'focusout', hide );
		card.tabIndex = 0;
	}

	/* ----------------------------------------------------------- connectors */

	/*
	 * One overlay for every line. Positions are measured off the DOM rather
	 * than computed from the model, so a card that wrapped to a second row, or
	 * grew because somebody opened it, still gets a line that lands on it.
	 */
	function connectors( links ) {
		var old = host.querySelector( '.vh-estate-wires' );
		if ( old ) { old.remove(); }
		var oldL = host.querySelector( '.vh-estate-labels' );
		if ( oldL ) { oldL.remove(); }

		var labels = [];

		var box = host.getBoundingClientRect();
		var ns  = 'http://www.w3.org/2000/svg';
		var svg = document.createElementNS( ns, 'svg' );
		svg.setAttribute( 'class', 'vh-estate-wires' );
		svg.setAttribute( 'width', String( box.width ) );
		svg.setAttribute( 'height', String( host.scrollHeight ) );
		svg.setAttribute( 'aria-hidden', 'true' );

		links.forEach( function ( link, i ) {
			var a = document.getElementById( 'n-' + link.from );
			var b = document.getElementById( 'n-' + link.to );
			if ( ! a || ! b ) { return; }

			var ra = a.getBoundingClientRect();
			var rb = b.getBoundingClientRect();

			// From the top edge of the lower card to the bottom edge of the upper one.
			var x1 = ra.left + ra.width / 2 - box.left;
			var y1 = ra.top - box.top;
			var x2 = rb.left + rb.width / 2 - box.left;
			var y2 = rb.bottom - box.top;

			var path = document.createElementNS( ns, 'path' );
			var mid  = ( y1 + y2 ) / 2;
			path.setAttribute( 'd', 'M' + x1 + ' ' + y1 + ' C ' + x1 + ' ' + mid + ', ' + x2 + ' ' + mid + ', ' + x2 + ' ' + y2 );
			// Coloured and animated by the lane it leaves, so a glance across
			// the diagram separates inspected traffic from the direct paths.
			path.setAttribute( 'class', 'vh-estate-wire vh-estate-wire--' + ( link.from.replace( /^(path|work|fw)-/, '' ) || 'x' ) );
			path.setAttribute( 'data-link', String( i ) );
			svg.appendChild( path );

			var head = document.createElementNS( ns, 'path' );
			head.setAttribute( 'd', 'M' + ( x2 - 4 ) + ' ' + ( y2 + 6 ) + ' L' + x2 + ' ' + y2 + ' L' + ( x2 + 4 ) + ' ' + ( y2 + 6 ) );
			head.setAttribute( 'class', 'vh-estate-arrow' );
			svg.appendChild( head );

			if ( link.label ) {
				/*
				 * Anchored just above the card the line *leaves*, not at the
				 * middle of the curve. Midpoints of several long curves land
				 * in the same small gap beside the tall firewall card and pile
				 * up; source cards are spread across the width, so anchoring
				 * to them separates the labels for free -- and puts each one
				 * beside the lane it is describing, which is where a reader
				 * looks for it anyway.
				 */
				labels.push( { text: link.label, x: x1, y: y1 - 13, link: i } );
			}
		} );

		host.appendChild( svg );
		placeLabels( labels );
		paint( links );
	}

	/*
	 * Labels as HTML, above everything, and nudged apart.
	 *
	 * Drawn inside the SVG they sat *under* the cards -- the overlay is below
	 * the bands so the wires do not cross the boxes -- and a long curve passing
	 * behind a tall card took its label with it. As positioned elements in
	 * their own layer they are always readable, and once they are boxes with
	 * real widths the overlaps can be resolved by measuring instead of by
	 * staggering and hoping.
	 */
	function placeLabels( labels ) {
		if ( ! labels.length ) { return; }

		var layer = el( 'div', 'vh-estate-labels' );
		host.appendChild( layer );

		/*
		 * Cards are obstacles, not just other labels. A label with an opaque
		 * background sitting on a card is readable and still wrong: it covers
		 * the thing it is annotating. Both are avoided in the same pass.
		 */
		var box = host.getBoundingClientRect();
		var placed = [];

		Array.prototype.forEach.call( host.querySelectorAll( '.vh-estate-card' ), function ( c ) {
			var r = c.getBoundingClientRect();
			placed.push( { x: r.left - box.left, y: r.top - box.top, w: r.width, h: r.height, card: true } );
		} );

		labels.forEach( function ( l ) {
			var tag = el( 'span', 'vh-estate-wirelabel' + ( /ALL/.test( l.text ) ? ' vh-estate-wirelabel--warn' : '' ), l.text );
			tag.setAttribute( 'data-link', String( l.link ) );
			tag.style.left = l.x + 'px';
			tag.style.top  = l.y + 'px';
			layer.appendChild( tag );

			var r = tag.getBoundingClientRect();
			var w = r.width, h = r.height;
			var x = l.x - w / 2, y = l.y - h / 2;

			/*
			 * Try upwards first, then downwards. The gap a label belongs in is
			 * between two bands; pushing only one way walks it into the band
			 * below and out of the gap it is meant to annotate.
			 */
			var hits = function ( ty ) {
				return placed.some( function ( q ) {
					return x < q.x + q.w + 6 && x + w + 6 > q.x && ty < q.y + q.h + 4 && ty + h + 4 > q.y;
				} );
			};

			if ( hits( y ) ) {
				var found = false;

				for ( var step = 1; step <= 14 && ! found; step++ ) {
					var up = y - step * ( h + 4 );
					var dn = y + step * ( h + 4 );

					if ( up > 0 && ! hits( up ) ) { y = up; found = true; }
					else if ( ! hits( dn ) ) { y = dn; found = true; }
				}
			}

			tag.style.left = x + 'px';
			tag.style.top  = y + 'px';
			tag.style.transform = 'none';
			placed.push( { x: x, y: y, w: w, h: h } );
		} );
	}

	/* ---------------------------------------------------------------- draw */

	function stats( data ) {
		var box = document.querySelector( '[data-vh-estate-stats]' );
		if ( ! box ) { return; }
		box.innerHTML = '';

		/*
		 * The device count is dropped when it is zero rather than printed as
		 * "0 network devices". An EC2 instance is a server, so the only thing
		 * that lands in this count is the inline firewall appliance -- and on
		 * an estate whose firewall account is not captured there is nothing to
		 * report. A zero would read as a finding; it is an absence.
		 */
		[
			[ data.totals.vpcs, 'VPC lanes' ],
			[ data.totals.servers, 'servers' ],
			[ data.totals.devices, 'network devices' ],
			[ data.totals.public, 'with a public address' ]
		].filter( function ( p ) {
			return 'network devices' !== p[1] || p[0] > 0;
		} ).forEach( function ( p ) {
			var s = el( 'span', 'vh-estate-stat' );
			s.appendChild( el( 'strong', null, ( p[0] || 0 ).toLocaleString() ) );
			s.appendChild( el( 'span', null, ' ' + p[1] ) );
			box.appendChild( s );
		} );
	}

	function render( data ) {
		host.innerHTML = '';

		if ( ! data || ! data.bands || ! ( data.bands[1].nodes || [] ).length ) {
			host.appendChild( el( 'p', 'vh-sub vh-muted', 'Nothing has been captured for this environment yet.' ) );
			return;
		}

		var redraw = function () { window.requestAnimationFrame( function () { connectors( data.links || [] ); } ); };

		data.bands.forEach( function ( band ) {
			if ( ! ( band.nodes || [] ).length ) { return; }

			var section = el( 'section', 'vh-estate-band vh-estate-band--' + band.id );
			section.appendChild( el( 'h2', 'vh-estate-band__h', band.label ) );

			var row = el( 'div', 'vh-estate-row' );
			band.nodes.forEach( function ( node ) {
				var card = 'dest' === band.id ? destCard( node )
					: ( 'work' === band.id ? workCard( node, redraw ) : midCard( node, redraw ) );

				if ( 'dest' !== band.id ) { bindTip( card, node ); }

				card.tabIndex = 0;
				card.setAttribute( 'role', 'button' );
				card.setAttribute( 'aria-label', 'Trace the path through ' + node.label );

				card.addEventListener( 'click', function ( ev ) {
					// A control inside the card does its own job; only the card
					// itself selects, or opening a list would also reroute the
					// diagram under the reader.
					if ( ev.target.closest( 'summary, a, button, input' ) ) { return; }
					select( node.id, data.links || [] );
				} );

				card.addEventListener( 'keydown', function ( ev ) {
					if ( 'Enter' === ev.key || ' ' === ev.key ) {
						if ( ev.target.closest( 'summary, a, button, input' ) ) { return; }
						ev.preventDefault();
						select( node.id, data.links || [] );
					}
				} );

				row.appendChild( card );
			} );
			section.appendChild( row );
			host.appendChild( section );
		} );

		stats( data );
		redraw();
	}

	/* ----------------------------------------------------------- selection */

	/*
	 * Click a node and the whole flow through it lights up: everything it
	 * reaches upwards, everything that reaches it from below, and the wires
	 * between them. Everything else dims rather than disappearing, because the
	 * question is "where does this go", not "hide the rest" -- the dimmed
	 * boxes are the context that makes the lit path mean something.
	 *
	 * Traversal is both directions from the clicked node. The graph is a DAG
	 * drawn bottom-up, so ancestors are the destinations and descendants are
	 * the workloads feeding it; a lane wants both halves or it answers half
	 * the question.
	 */
	var selected = null;

	function flowThrough( id, links ) {
		var up = {}, down = {}, wires = {};

		var walk = function ( from, seen, forward ) {
			var queue = [ from ];
			seen[ from ] = true;

			while ( queue.length ) {
				var at = queue.shift();

				links.forEach( function ( l, i ) {
					var next = forward ? ( l.from === at ? l.to : null ) : ( l.to === at ? l.from : null );
					if ( ! next || seen[ next ] ) { return; }
					wires[ i ] = true;
					seen[ next ] = true;
					queue.push( next );
				} );

				// A wire straight off the starting node counts even when its
				// far end was already reached from the other direction.
				links.forEach( function ( l, i ) {
					if ( ( forward && l.from === at ) || ( ! forward && l.to === at ) ) { wires[ i ] = true; }
				} );
			}
		};

		walk( id, up, true );
		walk( id, down, false );

		var nodes = {};
		Object.keys( up ).concat( Object.keys( down ) ).forEach( function ( k ) { nodes[ k ] = true; } );

		return { nodes: nodes, wires: wires };
	}

	function paint( links ) {
		var all = host.querySelectorAll( '.vh-estate-card' );
		var ws  = host.querySelectorAll( '.vh-estate-wire, .vh-estate-arrow' );
		var ls  = host.querySelectorAll( '.vh-estate-wirelabel' );

		if ( ! selected ) {
			[ all, ws, ls ].forEach( function ( set ) {
				Array.prototype.forEach.call( set, function ( e ) { e.classList.remove( 'is-lit', 'is-dim' ); } );
			} );
			host.classList.remove( 'has-selection' );
			return;
		}

		var f = flowThrough( selected, links );
		host.classList.add( 'has-selection' );

		Array.prototype.forEach.call( all, function ( e ) {
			var on = !! f.nodes[ e.id.replace( /^n-/, '' ) ];
			e.classList.toggle( 'is-lit', on );
			e.classList.toggle( 'is-dim', ! on );
			e.classList.toggle( 'is-origin', e.id === 'n-' + selected );
		} );

		Array.prototype.forEach.call( ws, function ( e ) {
			var on = !! f.wires[ e.getAttribute( 'data-link' ) ];
			e.classList.toggle( 'is-lit', on );
			e.classList.toggle( 'is-dim', ! on );
		} );

		Array.prototype.forEach.call( ls, function ( e ) {
			var on = !! f.wires[ e.getAttribute( 'data-link' ) ];
			e.classList.toggle( 'is-lit', on );
			e.classList.toggle( 'is-dim', ! on );
		} );
	}

	function select( id, links ) {
		selected = ( selected === id ) ? null : id;
		paint( links );
	}

	document.addEventListener( 'keydown', function ( ev ) {
		if ( 'Escape' === ev.key && selected && current ) { selected = null; paint( current.links || [] ); }
	} );

	host.addEventListener( 'click', function ( ev ) {
		if ( ! ev.target.closest( '.vh-estate-card' ) && selected && current ) { selected = null; paint( current.links || [] ); }
	} );

	var current = null;
	window.addEventListener( 'resize', function () {
		if ( current ) { connectors( current.links || [] ); }
	} );

	fetch( cfg.rest + ( host.dataset.vhEnv ? '?env=' + encodeURIComponent( host.dataset.vhEnv ) : '' ), {
		headers: { 'X-WP-Nonce': cfg.nonce },
		credentials: 'same-origin'
	} )
		.then( function ( r ) {
			if ( ! r.ok ) { throw new Error( 'HTTP ' + r.status ); }
			return r.json();
		} )
		.then( function ( data ) { current = data; render( data ); } )
		.catch( function ( e ) {
			host.innerHTML = '';
			host.appendChild( el( 'p', 'vh-notice vh-notice--warn', 'Could not read the estate topology: ' + ( e && e.message ) ) );
		} );
}() );
