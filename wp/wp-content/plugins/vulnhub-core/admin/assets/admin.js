/* global VulnHubAdmin, wp */
( function () {
	'use strict';

	var cfg = window.VulnHubAdmin || {};

	function api( path, options ) {
		options = options || {};
		return wp.apiFetch( {
			path: '/vulnhub/v1' + path,
			method: options.method || 'GET',
			data: options.data || undefined,
		} );
	}

	function busy( button, label ) {
		button.dataset.originalLabel = button.innerHTML;
		button.disabled = true;
		button.innerHTML = '<span class="vh-spinner"></span>' + label;
	}

	function idle( button ) {
		button.disabled = false;
		if ( button.dataset.originalLabel ) {
			button.innerHTML = button.dataset.originalLabel;
		}
	}

	/*
	 * The result of a test or a sync has to land somewhere the operator can
	 * see it. In wp-admin that is `.vulnhub-wrap`, with WordPress's own
	 * notice styling. The portal has neither, so the message went into the
	 * void -- a pressed button and complete silence. It gets its own
	 * container and its own classes instead.
	 */
	function flash( message, type ) {
		var wrap = document.querySelector( '.vulnhub-wrap' );
		// The portal renders its admin body as `.vh-adm__body` (with the
		// mirrored view inside `.vh-adm__view`); `.vh-admin__body` never
		// existed, so on the portal the result of a Test or a Sync landed
		// nowhere and the button looked inert. Match the real class, and fall
		// back to a floating toast so a message is ALWAYS visible even if the
		// markup changes again.
		var portal = wrap ? null : (
			document.querySelector( '.vh-adm__view' ) ||
			document.querySelector( '.vh-adm__body' )
		);

		var notice = document.createElement( 'div' );

		if ( wrap ) {
			notice.className = 'notice notice-' + ( type || 'info' ) + ' is-dismissible';
			notice.innerHTML = '<p>' + message + '</p>';
			wrap.insertBefore( notice, wrap.firstChild.nextSibling );
		} else if ( portal ) {
			notice.className = 'success' === type ? 'vh-flash vh-flash--good' : 'vh-warn-note';
			notice.textContent = message;
			portal.insertBefore( notice, portal.firstChild );
		} else {
			// Last resort: a toast pinned to the viewport, so feedback is
			// never silently swallowed regardless of the surrounding page.
			notice.className = 'vh-toast vh-toast--' + ( 'success' === type ? 'good' : ( 'error' === type ? 'bad' : 'info' ) );
			notice.setAttribute( 'role', 'status' );
			notice.textContent = message;
			document.body.appendChild( notice );
		}

		notice.scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
		window.setTimeout( function () {
			notice.remove();
		}, 9000 );
	}

	/* ---------------------------------------------------------------
	 * Connector test / sync buttons
	 * ------------------------------------------------------------- */
	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '[data-vh-action]' );
		if ( ! button ) {
			return;
		}

		var action = button.dataset.vhAction;
		var id = button.dataset.vhConnector;

		if ( action === 'test' ) {
			event.preventDefault();
			busy( button, cfg.i18n.testing );
			api( '/connectors/' + id + '/test', { method: 'POST' } )
				.then( function ( result ) {
					flash( result.message, result.ok ? 'success' : 'error' );
				} )
				.catch( function ( error ) {
					flash( error.message || cfg.i18n.genericError, 'error' );
				} )
				.finally( function () {
					idle( button );
				} );
		}

		if ( action === 'sync' ) {
			event.preventDefault();
			busy( button, cfg.i18n.syncing );
			api( '/connectors/' + id + '/sync', { method: 'POST', data: { force: true } } )
				.then( function ( result ) {
					flash( result.message || 'Sync finished.', result.ok ? 'success' : 'error' );
					if ( result.ok ) {
						window.setTimeout( function () {
							window.location.reload();
						}, 1200 );
					}
				} )
				.catch( function ( error ) {
					flash( error.message || cfg.i18n.genericError, 'error' );
				} )
				.finally( function () {
					idle( button );
				} );
		}

		if ( action === 'remap' ) {
			event.preventDefault();
			busy( button, 'Re-mapping…' );
			api( '/mapping/run', { method: 'POST' } )
				.then( function ( result ) {
					flash(
						'Processed ' + result.processed + ' assets, ' + result.changed +
							' updated, ' + result.unresolved + ' user-bound assets still unassigned.',
						result.unresolved > 0 ? 'warning' : 'success'
					);
					window.setTimeout( function () {
						window.location.reload();
					}, 1500 );
				} )
				.catch( function ( error ) {
					flash( error.message || cfg.i18n.genericError, 'error' );
				} )
				.finally( function () {
					idle( button );
				} );
		}

		if ( action === 'raise-ticket' ) {
			event.preventDefault();
			var findingIds = [];
			if ( button.dataset.vhFinding ) {
				findingIds = [ parseInt( button.dataset.vhFinding, 10 ) ];
			} else {
				document.querySelectorAll( '.vh-select-finding:checked' ).forEach( function ( box ) {
					findingIds.push( parseInt( box.value, 10 ) );
				} );
			}
			if ( ! findingIds.length ) {
				flash( 'Select at least one finding first.', 'warning' );
				return;
			}
			busy( button, 'Raising…' );
			api( '/tickets', { method: 'POST', data: { finding_ids: findingIds } } )
				.then( function ( result ) {
					flash( result.message || 'Ticket created.', 'success' );
					window.setTimeout( function () {
						window.location.reload();
					}, 1500 );
				} )
				.catch( function ( error ) {
					flash( error.message || cfg.i18n.genericError, 'error' );
				} )
				.finally( function () {
					idle( button );
				} );
		}

		if ( action === 'refresh-ticket' ) {
			event.preventDefault();
			busy( button, 'Refreshing…' );
			api( '/tickets/' + button.dataset.vhTicket + '/refresh', { method: 'POST' } )
				.then( function ( result ) {
					flash( result.message || 'Ticket refreshed.', result.ok ? 'success' : 'warning' );
					window.setTimeout( function () {
						window.location.reload();
					}, 1200 );
				} )
				.catch( function ( error ) {
					flash( error.message || cfg.i18n.genericError, 'error' );
				} )
				.finally( function () {
					idle( button );
				} );
		}
	} );

	/* ---------------------------------------------------------------
	 * Select-all checkbox on finding tables
	 * ------------------------------------------------------------- */
	document.addEventListener( 'change', function ( event ) {
		if ( ! event.target.matches( '.vh-select-all' ) ) {
			return;
		}
		var checked = event.target.checked;
		document.querySelectorAll( '.vh-select-finding' ).forEach( function ( box ) {
			box.checked = checked;
		} );
	} );

	/* ---------------------------------------------------------------
	 * Auto-submit filter selects
	 * ------------------------------------------------------------- */
	document.querySelectorAll( '.vh-filters [data-vh-autosubmit]' ).forEach( function ( field ) {
		field.addEventListener( 'change', function () {
			field.form.submit();
		} );
	} );

	/* ---------------------------------------------------------------
	 * Expand/collapse long log output
	 * ------------------------------------------------------------- */
	document.querySelectorAll( '[data-vh-toggle]' ).forEach( function ( trigger ) {
		trigger.addEventListener( 'click', function ( event ) {
			event.preventDefault();
			var target = document.getElementById( trigger.dataset.vhToggle );
			if ( target ) {
				target.hidden = ! target.hidden;
			}
		} );
	} );
}() );


/* =====================================================================
 * Connector sync progress.
 *
 * A sync writes a heartbeat and a running count as it imports; this polls
 * /sync-status and draws a moving bar with a rough ETA, or the failure if
 * it stopped. Self-contained (its own apiFetch calls) so it works whether
 * the card is shown in wp-admin or mirrored into the portal, and it starts
 * on its own for a sync already running when the page loads -- a scheduled
 * one, or a manual one whose long request is still in flight.
 * ===================================================================== */
( function () {
	'use strict';

	if ( ! window.wp || ! wp.apiFetch ) {
		return;
	}

	var timers = {};

	function esc( s ) {
		var d = document.createElement( 'div' );
		d.textContent = String( s == null ? '' : s );
		return d.innerHTML;
	}

	function dur( s ) {
		s = Math.max( 0, Math.round( Number( s ) || 0 ) );
		if ( s < 60 ) { return s + 's'; }
		var m = Math.floor( s / 60 ), ss = s % 60;
		if ( m < 60 ) { return ss ? m + 'm ' + ss + 's' : m + 'm'; }
		var h = Math.floor( m / 60 ); m = m % 60;
		return m ? h + 'h ' + m + 'm' : h + 'h';
	}

	function num( n ) {
		return ( Number( n ) || 0 ).toLocaleString();
	}

	function progressRow( label, cls, pct, meta ) {
		return '<div class="vh-sync-progress__row"><span class="vh-sync-progress__lbl">' + esc( label ) + '</span>' +
			'<div class="vh-sync-progress__bar' + cls + '"><span style="width:' + pct + '%"></span></div></div>' +
			'<div class="vh-sync-progress__meta">' + esc( meta ) + '</div>';
	}

	// Two bars for a staged sync: download to disk, then process off disk.
	function stagedBars( d ) {
		var dl = d.download || {};
		var pr = d.process || {};
		var mb = Math.round( ( dl.bytes || 0 ) / 1048576 );
		var estMb = Math.round( ( dl.est_bytes || 0 ) / 1048576 );
		var rateMb = ( dl.rate_bps || 0 ) / 1048576;
		var chunks = ( dl.vuln_chunks || 0 ) + ( dl.assets_chunks || 0 );
		var dlDone = 'download' !== d.phase;
		var haveEst = ! dlDone && estMb > mb;
		var dlPct = dlDone ? 100 : ( haveEst ? Math.min( 99, Math.round( 100 * mb / estMb ) ) : 100 );

		var dlBits;
		if ( dlDone ) {
			dlBits = [ num( chunks ) + ' chunks', mb + ' MB' ];
		} else {
			dlBits = [ num( chunks ) + ' chunks', mb + ' MB' + ( haveEst ? ' of ~' + num( estMb ) + ' MB' : '' ) ];
			if ( rateMb >= 0.1 ) { dlBits.push( rateMb.toFixed( rateMb < 10 ? 1 : 0 ) + ' MB/s' ); }
			if ( dl.eta != null ) { dlBits.push( '~' + dur( dl.eta ) + ' left' ); }
		}

		var dlBar = progressRow(
			'Download',
			( dlDone || haveEst ) ? '' : ' is-indeterminate',
			dlPct,
			( dlDone ? 'Downloaded ' : 'Downloading… ' ) + dlBits.join( ' · ' )
		);

		var total = pr.records_total || 0;
		var done = pr.records_done || 0;
		var active = 'process' === d.phase;
		var pct = ( active && total > 0 ) ? Math.min( 99, Math.round( 100 * done / total ) ) : ( active ? 100 : 0 );
		var meta = active
			? ( num( done ) + ' / ' + num( total ) + ' records' + ( d.rate ? ' · ' + d.rate + '/s' : '' ) + ( d.eta != null ? ' · ~' + dur( d.eta ) + ' left' : '' ) )
			: ( 'download' === d.phase ? 'Waiting for the download to finish…' : 'Finishing up…' );

		var pBar = progressRow(
			'Process',
			( active && total > 0 ) ? '' : ( active ? ' is-indeterminate' : '' ),
			active ? pct : 0,
			meta
		);

		return dlBar + pBar;
	}

	// Returns true while the run is live (keep polling), false when terminal.
	function render( box, d ) {
		if ( ! d || 'idle' === d.state ) {
			box.hidden = true;
			box.innerHTML = '';
			return false;
		}

		box.hidden = false;

		if ( 'running' === d.state ) {
			// Staged sync: two bars -- download, then processing.
			if ( d.phase ) {
				box.innerHTML = stagedBars( d );
				return true;
			}

			var determinate = d.estimate > 0;
			var pct = determinate ? Math.min( 99, Math.round( 100 * d.done / d.estimate ) ) : 100;
			var bits = [ d.stage || 'Syncing', num( d.done ) + ' records' ];
			if ( d.rate ) { bits.push( d.rate + '/s' ); }
			if ( d.eta != null ) { bits.push( '~' + dur( d.eta ) + ' left' ); }
			bits.push( dur( d.elapsed ) + ' elapsed' );

			box.innerHTML =
				'<div class="vh-sync-progress__bar' + ( determinate ? '' : ' is-indeterminate' ) +
				'"><span style="width:' + pct + '%"></span></div>' +
				'<div class="vh-sync-progress__meta">' + esc( bits.join( ' · ' ) ) + '</div>';
			return true;
		}

		if ( 'failed' === d.state ) {
			box.innerHTML =
				'<div class="vh-sync-progress__done vh-sync-progress__done--bad">' +
				esc( ( d.stalled ? 'Sync stalled. ' : 'Sync failed. ' ) + ( d.message || '' ) ) +
				'</div>';
			return false;
		}

		if ( 'ok' === d.state ) {
			box.innerHTML =
				'<div class="vh-sync-progress__done vh-sync-progress__done--good">' +
				esc( 'Sync complete — ' + num( d.processed ) + ' records in ' + dur( ( d.duration_ms || 0 ) / 1000 ) ) +
				'</div>';
			return false;
		}

		return false;
	}

	function poll( id ) {
		var box = document.querySelector( '[data-vh-sync-progress="' + id + '"]' );
		if ( ! box ) { return; }

		wp.apiFetch( { path: '/vulnhub-dashboard/v1/sync-status?connector=' + encodeURIComponent( id ) } )
			.then( function ( d ) {
				var live = render( box, d );
				if ( timers[ id ] ) { window.clearTimeout( timers[ id ] ); }
				if ( live ) {
					timers[ id ] = window.setTimeout( function () { poll( id ); }, 4000 );
				} else {
					delete timers[ id ];
				}
			} )
			.catch( function () {
				delete timers[ id ];
			} );
	}

	document.addEventListener( 'click', function ( e ) {
		var b = e.target.closest( '[data-vh-action="sync"]' );
		if ( b && b.dataset.vhConnector ) {
			window.setTimeout( function () { poll( b.dataset.vhConnector ); }, 600 );
		}
	} );

	function init() {
		document.querySelectorAll( '[data-vh-sync-progress]' ).forEach( function ( box ) {
			poll( box.getAttribute( 'data-vh-sync-progress' ) );
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );
