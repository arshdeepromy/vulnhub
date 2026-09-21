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
	/**
	 * Ask, in the page.
	 *
	 * window.confirm() cannot be styled, cannot say more than one paragraph
	 * readably, and looks like a browser warning rather than part of the
	 * product. This is the same question in a dialog the page owns.
	 *
	 * @param {string}   message What is about to happen.
	 * @param {string}   go      Label for the button that does it.
	 * @param {Function} then    Called only if they say yes.
	 */
	function ask( message, go, then ) {
		if ( typeof HTMLDialogElement === 'undefined' ) {
			// No <dialog> support: better a browser box than no question.
			if ( window.confirm( message ) ) { then(); }
			return;
		}

		var dlg = document.createElement( 'dialog' );
		dlg.className = 'vh-ask';
		dlg.innerHTML =
			'<p class="vh-ask__msg"></p>' +
			'<div class="vh-ask__foot">' +
				'<button type="button" class="vh-btn vh-btn--sm" data-no></button>' +
				'<button type="button" class="vh-btn vh-btn--sm vh-btn--primary" data-yes></button>' +
			'</div>';

		dlg.querySelector( '.vh-ask__msg' ).textContent = message;
		dlg.querySelector( '[data-no]' ).textContent = 'Cancel';
		dlg.querySelector( '[data-yes]' ).textContent = go;

		document.body.appendChild( dlg );

		var close = function () { dlg.close(); dlg.remove(); };

		dlg.querySelector( '[data-no]' ).addEventListener( 'click', close );
		dlg.querySelector( '[data-yes]' ).addEventListener( 'click', function () { close(); then(); } );
		dlg.addEventListener( 'cancel', function () { dlg.remove(); } );

		dlg.showModal();
		dlg.querySelector( '[data-no]' ).focus();
	}

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

			var full = button.getAttribute( 'data-vh-full' ) === '1';
			// Not data-vh-confirm: the portal's app.js confirms those itself, which
			// would ask twice on the portal copy of this screen.
			var question = button.getAttribute( 'data-vh-sync-confirm' );

			if ( question ) {
				ask( question, full ? 'Run full resync' : ( button.getAttribute( 'data-vh-assets-only' ) === '1' ? 'Refresh assets' : 'Sync now' ), function () { run(); } );
				return;
			}

			run();
		}

		function run() {
			var full = button.getAttribute( 'data-vh-full' ) === '1';
			var assetsOnly = button.getAttribute( 'data-vh-assets-only' ) === '1';

			var payload = { force: true };
			if ( full ) { payload.full = true; }
			else if ( assetsOnly ) { payload.assets_only = true; }

			busy( button, cfg.i18n.syncing );
			api( '/connectors/' + id + '/sync', { method: 'POST', data: payload } )
				.then( function ( result ) {
					flash( result.message || 'Sync finished.', result.ok ? 'success' : 'error' );

					/*
					 * No reload. The sync runs in the background and this
					 * screen already polls it into the progress line below the
					 * card -- reloading a second after starting threw that
					 * away, replaced a live view with a page flash, and lost
					 * whatever else was on screen. The poller takes it from
					 * here and updates the card when it finishes.
					 */
					if ( result.ok ) {
						// The poller lives in another closure on this page, so
						// say what happened rather than reaching into it.
						document.dispatchEvent( new CustomEvent( 'vulnhub:sync-started', { detail: { connector: id } } ) );
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

		/*
		 * records_total is only a floor -- the connector sets it to the asset
		 * count because the real total is not known until every record is
		 * parsed, and findings then push records_done well past it. So it is a
		 * ratio only while it still is one: past the floor this showed
		 * "98,000 / 587 records" against a bar pinned at 99%, which is a
		 * progress bar lying twice. Past it, count up and say so.
		 */
		var ratio = total > 0 && done <= total;
		var pct = ( active && ratio ) ? Math.min( 99, Math.round( 100 * done / total ) ) : ( active ? 100 : 0 );
		var counted = ratio ? num( done ) + ' / ' + num( total ) + ' records' : num( done ) + ' records';
		var meta = active
			? ( counted + ( d.rate ? ' · ' + d.rate + '/s' : '' ) + ( ratio && d.eta != null ? ' · ~' + dur( d.eta ) + ' left' : '' ) )
			: ( 'download' === d.phase ? 'Waiting for the download to finish…' : 'Finishing up…' );

		var pBar = progressRow(
			'Process',
			( active && ratio ) ? '' : ( active ? ' is-indeterminate' : '' ),
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

			// The card still says when it last synced. Without a reload that
			// line is now wrong, and a wrong timestamp beside a "complete" is
			// worse than no timestamp.
			freshen( box, d );
			return false;
		}

		return false;
	}

	/**
	 * Update a card's "Synced … · took …" line from a finished run.
	 *
	 * @param {Element} box The progress box, which knows its connector id.
	 * @param {Object}  d   The sync-status payload.
	 */
	function freshen( box, d ) {
		var id = box.getAttribute( 'data-vh-sync-progress' );
		var el = id && document.querySelector( '[data-vh-last-sync="' + id + '"]' );

		if ( ! el ) { return; }

		el.textContent = 'Synced just now · took ' + dur( ( d.duration_ms || 0 ) / 1000 );
		el.removeAttribute( 'title' );
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
			// An integration card shows its progress line only once somebody
			// asks for a sync; on load the card's own status already says it.
			var card = b.closest( '.vh-intg__card' );
			if ( card ) { card.classList.add( 'is-syncing' ); }
			window.setTimeout( function () { poll( b.dataset.vhConnector ); }, 600 );
		}
	} );

	/*
	 * A sync was accepted. Look for it, and keep looking for a few seconds: a
	 * run that has been queued but has not yet written its first status reads
	 * as "idle", and a single look would give up on it and leave the card
	 * showing nothing at all.
	 */
	document.addEventListener( 'vulnhub:sync-started', function ( e ) {
		var id = e.detail && e.detail.connector;
		if ( ! id ) { return; }

		var tries = 0;
		( function look() {
			if ( timers[ id ] ) { return; }   // already live; the poller has it

			poll( id );
			tries++;

			if ( tries < 8 ) { window.setTimeout( look, 1500 ); }
		}() );
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

	/* ---------------------------------------------------------------
	 * Only the settings that belong to the chosen source
	 *
	 * The CMDB connector can read from ServiceNow, Jira Assets, a
	 * Confluence page or a CSV, and the form asked for all four sets at
	 * once: twenty-odd inputs, most of them irrelevant whichever way the
	 * Source system select was set. A field can now name the setting it
	 * belongs to (`show_when` in the connector's field definition), and
	 * this hides the rows that do not apply.
	 *
	 * Hidden rows keep their values -- switching source and back does not
	 * lose what was typed, and a save still posts every field, so an
	 * operator who configured ServiceNow last year does not have it wiped
	 * by saving while Assets is selected.
	 * ------------------------------------------------------------- */
	( function () {
		var rows = document.querySelectorAll( '[data-vh-when-field]' );

		if ( ! rows.length ) {
			return;
		}

		function apply() {
			rows.forEach( function ( row ) {
				var field = row.getAttribute( 'data-vh-when-field' );
				var want = ( row.getAttribute( 'data-vh-when-value' ) || '' ).split( ',' );
				var control = document.querySelector( '[name="' + field + '"]' );

				if ( ! control ) {
					return;
				}

				row.hidden = want.indexOf( control.value ) === -1;
			} );
		}

		// One listener per control, not per row: a dozen rows can hang off
		// the same select.
		var controls = {};

		rows.forEach( function ( row ) {
			controls[ row.getAttribute( 'data-vh-when-field' ) ] = true;
		} );

		Object.keys( controls ).forEach( function ( name ) {
			var control = document.querySelector( '[name="' + name + '"]' );

			if ( control ) {
				control.addEventListener( 'change', apply );
			}
		} );

		apply();
	}() );

}() );
