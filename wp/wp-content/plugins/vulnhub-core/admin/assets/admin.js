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
		var portal = wrap ? null : document.querySelector( '.vh-admin__body' );
		var host = wrap || portal;

		if ( ! host ) {
			return;
		}

		var notice = document.createElement( 'div' );

		if ( portal ) {
			notice.className = 'success' === type ? 'vh-flash vh-flash--good' : 'vh-warn-note';
			notice.textContent = message;
			host.insertBefore( notice, host.firstChild );
		} else {
			notice.className = 'notice notice-' + ( type || 'info' ) + ' is-dismissible';
			notice.innerHTML = '<p>' + message + '</p>';
			wrap.insertBefore( notice, wrap.firstChild.nextSibling );
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

