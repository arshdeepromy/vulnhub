/* global VulnHubApp, wp */
/**
 * Progressive enhancement only. Every chart and table is already complete when
 * this file never runs — this adds hover detail, the theme toggle, and the
 * one-click ticket action.
 */
( function () {
	'use strict';

	var cfg = window.VulnHubApp || { i18n: {} };

	/*
	 * All / None on the export column picker.
	 *
	 * Delegated, because a picker is rendered per screen and more than one
	 * can be on a page. Everything else about the picker is plain HTML --
	 * this is an accelerator, not a dependency.
	 */
	document.addEventListener( 'click', function ( e ) {
		var btn = e.target && e.target.closest ? e.target.closest( '[data-vh-cols]' ) : null;

		if ( ! btn ) {
			return;
		}

		var form = btn.closest( 'form' );

		if ( ! form ) {
			return;
		}

		var on = 'all' === btn.getAttribute( 'data-vh-cols' );

		Array.prototype.forEach.call(
			form.querySelectorAll( 'input[name="cols[]"]' ),
			function ( box ) {
				box.checked = on;
			}
		);
	} );

	/* ---------------------------------------------------------------
	 * Export popover: motion, Escape, and click-away
	 *
	 * <details> hides its content the instant `open` flips, so a closing
	 * animation has to be played *before* the flip -- CSS alone can only
	 * animate the opening. Everything here is an enhancement: with no
	 * scripting the disclosure still opens, still submits, still exports.
	 * ------------------------------------------------------------- */
	function vhExportReduced() {
		return !! ( window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches );
	}

	function vhExportClose( d ) {
		if ( ! d || ! d.open || d.classList.contains( 'is-closing' ) ) {
			return;
		}

		var panel = d.querySelector( '.vh-export__panel' );

		if ( ! panel || vhExportReduced() ) {
			d.open = false;
			return;
		}

		d.classList.add( 'is-closing' );

		// Belt and braces: if the animation never fires (display:none in a
		// print stylesheet, a browser that skips it), the panel must still
		// close rather than stick open with a half-applied class.
		var settle = window.setTimeout( function () {
			d.classList.remove( 'is-closing' );
			d.open = false;
		}, 240 );

		panel.addEventListener(
			'animationend',
			function () {
				window.clearTimeout( settle );
				d.classList.remove( 'is-closing' );
				d.open = false;
			},
			{ once: true }
		);
	}

	document.addEventListener( 'click', function ( e ) {
		if ( ! e.target || ! e.target.closest ) {
			return;
		}

		var summary = e.target.closest( '.vh-export > summary' );

		if ( summary ) {
			var own = summary.parentElement;

			// Let the browser open it; intercept only the close, which is
			// the half that needs frames before the content disappears.
			if ( own.open ) {
				e.preventDefault();
				vhExportClose( own );
			}

			return;
		}

		Array.prototype.forEach.call(
			document.querySelectorAll( '.vh-export[open]' ),
			function ( d ) {
				if ( ! d.contains( e.target ) ) {
					vhExportClose( d );
				}
			}
		);
	} );

	document.addEventListener( 'keydown', function ( e ) {
		if ( 'Escape' !== e.key && 'Esc' !== e.key ) {
			return;
		}

		Array.prototype.forEach.call(
			document.querySelectorAll( '.vh-export[open]' ),
			function ( d ) {
				var summary = d.querySelector( 'summary' );

				vhExportClose( d );

				// Send focus back to the control that opened the panel,
				// otherwise Escape strands a keyboard user at the top of
				// the document.
				if ( summary ) {
					summary.focus();
				}
			}
		);
	} );

	var tooltip = document.getElementById( 'vh-tooltip' );

	/* ---------------------------------------------------------------
	 * Theme toggle
	 * ------------------------------------------------------------- */
	function currentTheme() {
		var stamped = document.documentElement.getAttribute( 'data-theme' );
		if ( stamped ) {
			return stamped;
		}
		// Nothing stamped means the stylesheet's default, and that is dark:
		// there is no prefers-color-scheme rule in the CSS. Asking the OS here
		// made the first click on a light-mode machine "switch" to dark -- the
		// theme already on screen -- so it appeared to do nothing.
		return 'dark';
	}

	document.addEventListener( 'click', function ( event ) {
		if ( ! event.target.closest( '[data-vh-theme]' ) ) {
			return;
		}
		var next = currentTheme() === 'dark' ? 'light' : 'dark';
		document.documentElement.setAttribute( 'data-theme', next );
		try {
			localStorage.setItem( 'vh-theme', next );
		} catch ( e ) {}
	} );

	/* ---------------------------------------------------------------
	 * Tooltip helpers
	 * ------------------------------------------------------------- */
	function showTip( html, x, y ) {
		if ( ! tooltip ) {
			return;
		}
		tooltip.innerHTML = html;
		tooltip.hidden = false;

		var pad = 12;
		var rect = tooltip.getBoundingClientRect();
		var left = x + pad;
		var top = y + pad;

		if ( left + rect.width > window.innerWidth - 8 ) {
			left = x - rect.width - pad;
		}
		if ( top + rect.height > window.innerHeight - 8 ) {
			top = y - rect.height - pad;
		}

		tooltip.style.left = Math.max( 8, left ) + 'px';
		tooltip.style.top = Math.max( 8, top ) + 'px';
	}

	function hideTip() {
		if ( tooltip ) {
			tooltip.hidden = true;
		}
	}

	/* ---------------------------------------------------------------
	 * Line-chart crosshair
	 * ------------------------------------------------------------- */
	document.querySelectorAll( '[data-vh-chart="line"]' ).forEach( function ( svg ) {
		var crosshair = svg.querySelector( '.vh-crosshair' );

		svg.querySelectorAll( '.vh-hit' ).forEach( function ( hit ) {
			function enter( event ) {
				if ( crosshair ) {
					var x = hit.getAttribute( 'data-x' );
					crosshair.setAttribute( 'x1', x );
					crosshair.setAttribute( 'x2', x );
					crosshair.hidden = false;
				}
				showTip(
					'<strong>' + hit.getAttribute( 'data-label' ) + '</strong><br>' +
						hit.getAttribute( 'data-values' ),
					event.clientX,
					event.clientY
				);
			}
			hit.addEventListener( 'mouseenter', enter );
			hit.addEventListener( 'mousemove', enter );
			hit.addEventListener( 'mouseleave', function () {
				if ( crosshair ) {
					crosshair.hidden = true;
				}
				hideTip();
			} );
		} );
	} );

	/* ---------------------------------------------------------------
	 * Generic hover tooltips (stacked segments, mini bars)
	 * ------------------------------------------------------------- */
	document.addEventListener( 'mouseover', function ( event ) {
		var el = event.target.closest( '[data-vh-tip]' );
		if ( el ) {
			showTip( el.getAttribute( 'data-vh-tip' ), event.clientX, event.clientY );
		}
	} );
	document.addEventListener( 'mouseout', function ( event ) {
		if ( event.target.closest( '[data-vh-tip]' ) ) {
			hideTip();
		}
	} );
	window.addEventListener( 'scroll', hideTip, { passive: true } );

	/* ---------------------------------------------------------------
	 * Select all / raise ticket
	 * ------------------------------------------------------------- */
	/*
	 * Selection state for the findings list.
	 *
	 * Two modes. In "page" mode the ticked rows are exactly what is selected,
	 * and the export carries their ids. In "all" mode the reader has asked for
	 * every finding the filter matches -- more than one page of them -- so the
	 * export carries the filter and no ids, and the whole set comes back. The
	 * bar shows which is in force and how many that is.
	 */
	var selMode = 'page';

	function selBar() {
		return document.querySelector( '[data-vh-selbar]' );
	}

	function selChecked() {
		return document.querySelectorAll( '.vh-pick:checked' ).length;
	}

	function selRefresh() {
		var bar = selBar();
		if ( ! bar ) { return; }

		var total   = parseInt( bar.getAttribute( 'data-vh-total' ), 10 ) || 0;
		var checked = selChecked();
		var countEl = bar.querySelector( '[data-vh-selcount]' );
		var allBtn  = bar.querySelector( '[data-vh-selall]' );

		if ( 'all' === selMode ) {
			bar.hidden = false;
			if ( countEl ) { countEl.textContent = ( cfg.i18n.selAll || 'All %d findings selected' ).replace( '%d', total.toLocaleString() ); }
			if ( allBtn ) { allBtn.hidden = true; }
			return;
		}

		if ( checked < 1 ) {
			bar.hidden = true;
			return;
		}

		bar.hidden = false;
		if ( countEl ) { countEl.textContent = ( cfg.i18n.selCount || '%d selected' ).replace( '%d', checked.toLocaleString() ); }

		// Offer "select every match" only when there are more than the ticked.
		if ( allBtn ) {
			if ( total > checked ) {
				allBtn.hidden = false;
				allBtn.textContent = ( cfg.i18n.selAllMatching || 'Select all %d matching these filters' ).replace( '%d', total.toLocaleString() );
			} else {
				allBtn.hidden = true;
			}
		}
	}

	// Header box: tick/untick every rendered row; drop out of "all" mode.
	document.addEventListener( 'change', function ( event ) {
		if ( event.target.matches( '[data-vh-all]' ) ) {
			selMode = 'page';
			var on = event.target.checked;
			document.querySelectorAll( '.vh-pick' ).forEach( function ( box ) { box.checked = on; } );
			selRefresh();
			return;
		}
		if ( event.target.matches( '.vh-pick' ) ) {
			selMode = 'page';
			selRefresh();
		}
	} );

	// "Select all N matching these filters".
	document.addEventListener( 'click', function ( event ) {
		if ( ! event.target.closest( '[data-vh-selall]' ) ) { return; }
		selMode = 'all';
		document.querySelectorAll( '.vh-pick' ).forEach( function ( box ) { box.checked = true; } );
		selRefresh();
	} );

	// Clear the selection.
	document.addEventListener( 'click', function ( event ) {
		if ( ! event.target.closest( '[data-vh-selclear]' ) ) { return; }
		selMode = 'page';
		document.querySelectorAll( '.vh-pick' ).forEach( function ( box ) { box.checked = false; } );
		var all = document.querySelector( '[data-vh-all]' );
		if ( all ) { all.checked = false; }
		selRefresh();
	} );

	/*
	 * Export the selection. Reuses the column-picker form already on the page
	 * for its endpoint, nonce and carried filters, so this is the same export
	 * with either an explicit id set (page mode) or none (all mode). Leaving
	 * cols off means every column, which is what an unopened picker gives.
	 */
	document.addEventListener( 'click', function ( event ) {
		if ( ! event.target.closest( '[data-vh-selexport]' ) ) { return; }

		var form = document.querySelector( '.vh-export__panel' );
		if ( ! form ) { toast( cfg.i18n.error || 'Export is unavailable.', 'warn' ); return; }

		var params = new URLSearchParams();
		form.querySelectorAll( 'input[name]' ).forEach( function ( input ) {
			if ( 'cols[]' === input.name ) { return; } // omit -> all columns
			if ( input.name ) { params.set( input.name, input.value ); }
		} );

		if ( 'all' !== selMode ) {
			var ids = [];
			document.querySelectorAll( '.vh-pick:checked' ).forEach( function ( box ) { ids.push( box.value ); } );
			if ( ! ids.length ) { toast( cfg.i18n.noSelect || 'Nothing selected.', 'warn' ); return; }
			params.set( 'ids', ids.join( ',' ) );
		}

		var action = form.getAttribute( 'action' ) || '';
		window.location.href = action + ( action.indexOf( '?' ) === -1 ? '?' : '&' ) + params.toString();
	} );

	function toast( message, tone ) {
		var el = document.createElement( 'div' );
		el.className = 'vh-toast vh-toast--' + ( tone || 'info' );
		el.setAttribute( 'role', 'status' );
		el.textContent = message;
		document.body.appendChild( el );
		window.setTimeout( function () {
			el.classList.add( 'is-out' );
			window.setTimeout( function () {
				el.remove();
			}, 400 );
		}, 5000 );
	}

	/* ---------------------------------------------------------------
	 * Raise ticket: review everything before it is sent.
	 *
	 * The server builds the exact issue -- fields, description, the CSV that
	 * will be attached -- and keeps it under a token. This dialog shows that
	 * draft and nothing else; Send transmits the draft by its token, so what
	 * was reviewed is what travels. Changing the attachment's columns builds
	 * a fresh draft.
	 * ------------------------------------------------------------- */
	var review = null;

	function el( tag, cls, text ) {
		var node = document.createElement( tag );
		if ( cls ) { node.className = cls; }
		if ( null != text ) { node.textContent = String( text ); }
		return node;
	}

	function reviewDialog() {
		if ( review ) { return review; }

		// Not `vh-modal`: that class also styles the drill-down overlays, which
		// centre their contents and clipped this dialog's sections.
		var d = el( 'dialog', 'vh-review' );
		d.setAttribute( 'aria-labelledby', 'vh-review-title' );
		d.innerHTML =
			'<form method="dialog" class="vh-modal__x"><button aria-label="Close">&times;</button></form>' +
			'<h2 id="vh-review-title">Review before sending to Jira</h2>' +
			'<p class="vh-review__lede">Nothing has been sent. This is exactly what will travel to Jira when you press Send.</p>' +
			'<div class="vh-review__body" data-vh-review-body></div>' +
			'<div class="vh-review__foot">' +
				'<span class="vh-review__status" data-vh-review-status role="status"></span>' +
				'<button type="button" class="vh-btn vh-btn--ghost" data-vh-review-cancel>Cancel</button>' +
				'<button type="button" class="vh-btn vh-btn--primary" data-vh-review-send disabled>Send to Jira</button>' +
			'</div>';
		document.body.appendChild( d );

		d.querySelector( '[data-vh-review-cancel]' ).addEventListener( 'click', function () { d.close(); } );
		review = d;
		return d;
	}

	/*
	 * Auto-dismiss, for the success state only.
	 *
	 * Once the issue exists the dialog has nothing left to say, and the list
	 * behind it is out of date the moment the findings are ticketed -- so the
	 * timer reloads rather than just closing, which is what the Close button
	 * already did. The review state never gets a timer: a dialog that closes
	 * while somebody is reading what is about to be sent is worse than one
	 * they have to dismiss.
	 *
	 * Any sign of a human -- a pointer over it, focus moving inside it, a key
	 * -- stops the clock for good. Five seconds is not long enough to read a
	 * ticket key and decide to open it, and a countdown that ignores you while
	 * you reach for a button is how a convenience becomes an obstacle.
	 */
	var closeTimer = null;

	function stopCountdown( d, why ) {
		if ( ! closeTimer ) { return; }
		window.clearInterval( closeTimer );
		closeTimer = null;

		var status = d.querySelector( '[data-vh-review-status]' );
		if ( status ) {
			status.removeAttribute( 'aria-live' );
			status.textContent = why || '';
		}
	}

	function countdownToClose( d, seconds ) {
		var status = d.querySelector( '[data-vh-review-status]' );
		var left   = seconds;

		stopCountdown( d, '' );

		var say = function () {
			status.textContent = 'Closing in ' + left + 's — the list refreshes.';
		};

		say();
		/* Announced once, then silent: a screen reader counting down from five
		   is noise, not information. */
		status.setAttribute( 'aria-live', 'off' );

		closeTimer = window.setInterval( function () {
			left -= 1;

			if ( left > 0 ) {
				say();
				return;
			}

			stopCountdown( d, '' );
			d.close();
			window.location.reload();
		}, 1000 );

		/*
		 * One listener per dialog, attached once; the dialog is reused.
		 *
		 * `pointerover`, not `pointerenter`: enter does not bubble, so its
		 * target is whichever child sits under the cursor and a listener on
		 * the dialog never runs. It looked wired -- keydown cancelled, the
		 * pointer did not -- and only a capture-phase probe showed the event
		 * arriving at all. `focusin` and `keydown` bubble, so those are fine.
		 */
		if ( ! d.dataset.vhHoldWired ) {
			d.dataset.vhHoldWired = '1';
			[ 'pointerover', 'mouseover', 'focusin', 'keydown' ].forEach( function ( ev ) {
				d.addEventListener( ev, function () { stopCountdown( d, 'Staying open.' ); } );
			} );
			// Dismissed by hand: nothing left to fire.
			d.addEventListener( 'close', function () { stopCountdown( d, '' ); } );
		}
	}

	function section( title ) {
		var s = el( 'section', 'vh-review__sec' );
		s.appendChild( el( 'h3', null, title ) );
		return s;
	}

	function renderDraft( d, draft, request ) {
		var body = d.querySelector( '[data-vh-review-body]' );
		var send = d.querySelector( '[data-vh-review-send]' );
		var status = d.querySelector( '[data-vh-review-status]' );
		body.innerHTML = '';
		status.textContent = '';

		if ( ! draft || ! draft.ok ) {
			var bad = el( 'div', 'vh-notice vh-notice--warn', ( draft && draft.message ) || cfg.i18n.error );
			body.appendChild( bad );
			send.disabled = true;
			return;
		}

		( draft.warnings || [] ).forEach( function ( w ) {
			body.appendChild( el( 'div', 'vh-notice vh-notice--warn', w ) );
		} );

		// Scope.
		var sc = draft.scope || {};
		var scope = section( 'What this ticket covers' );
		scope.appendChild( el( 'p', 'vh-review__big', 'assets' === sc.kind
			? '1 ticket · ' + sc.assets + ' asset' + ( 1 === sc.assets ? '' : 's' ) + ( sc.request ? ' · ' + sc.request : '' )
			: '1 ticket · ' + sc.eligible + ' finding' + ( 1 === sc.eligible ? '' : 's' ) + ' · ' + sc.assets + ' asset' + ( 1 === sc.assets ? '' : 's' ) ) );
		if ( sc.skipped ) {
			scope.appendChild( el( 'p', 'vh-sub', sc.skipped + ' selected finding' + ( 1 === sc.skipped ? ' is' : 's are' ) + ' already on an open ticket (' + ( sc.on_tickets || [] ).join( ', ' ) + ') and will be left out.' ) );
		}
		body.appendChild( scope );

		// Fields.
		var fs = section( 'Fields sent to Jira' );
		var dl = el( 'dl', 'vh-review__fields' );
		( draft.fields || [] ).forEach( function ( pair ) {
			dl.appendChild( el( 'dt', null, pair[0] ) );

			// The due date can be changed here. A change builds a fresh draft,
			// so the description's SLA line always matches the date sent.
			if ( 'Due date' === pair[0] && draft.due ) {
				var dd = el( 'dd', 'vh-review__due' );
				var date = el( 'input' );
				date.type = 'date';
				date.value = draft.due.value || '';
				date.min = draft.due.min || '';
				date.setAttribute( 'aria-label', 'Due date' );
				date.addEventListener( 'change', function () {
					if ( ! date.value ) { return; }
					request.due_date = date.value;
					loadDraft( d, request, true );
				} );
				dd.appendChild( date );
				dd.appendChild( el( 'span', 'vh-sub', request.due_date ? ' set by you' : ' from the SLA; change it to set your own' ) );
				dl.appendChild( dd );
				return;
			}

			// Urgency / Impact: dropdowns of the options Jira lists, not set by default.
			var select = ( draft.selects || [] ).filter( function ( s ) { return s.label === pair[0]; } )[0];
			if ( select ) {
				var sd = el( 'dd', 'vh-review__due' );
				var ss = el( 'select' );
				ss.setAttribute( 'aria-label', select.label );
				var blank = el( 'option', null, 'Not set' );
				blank.value = 'none';
				ss.appendChild( blank );
				select.options.forEach( function ( o ) {
					var opt = el( 'option', null, o.value );
					opt.value = o.id;
					ss.appendChild( opt );
				} );
				ss.value = select.value || 'none';
				ss.addEventListener( 'change', function () {
					request.selects = request.selects || {};
					request.selects[ select.key ] = ss.value;
					loadDraft( d, request, true );
				} );
				sd.appendChild( ss );
				dl.appendChild( sd );
				return;
			}

			// Priority: the values the project really allows, read from Jira.
			if ( 'Priority' === pair[0] && draft.priority ) {
				var pd = el( 'dd', 'vh-review__due' );
				var sel = el( 'select' );
				sel.setAttribute( 'aria-label', 'Priority' );
				var none = el( 'option', null, 'Not set' + ( draft.priority.default ? ' (Jira default: ' + draft.priority.default + ')' : ' (Jira default)' ) );
				none.value = 'none';
				sel.appendChild( none );
				var opts = ( draft.priority.options || [] ).slice();
				if ( draft.priority.value && opts.indexOf( draft.priority.value ) === -1 ) { opts.push( draft.priority.value ); }
				opts.forEach( function ( name ) {
					var o = el( 'option', null, name );
					o.value = name;
					sel.appendChild( o );
				} );
				sel.value = draft.priority.value || 'none';
				sel.addEventListener( 'change', function () {
					request.priority = sel.value;
					loadDraft( d, request, true );
				} );
				pd.appendChild( sel );
				dl.appendChild( pd );
				return;
			}

			dl.appendChild( el( 'dd', null, pair[1] ) );
		} );
		fs.appendChild( dl );
		body.appendChild( fs );

		// Description (server-rendered and escaped from the exact ADF sent).
		// Editable: the text goes back to the server, which turns it into the
		// document it stores and sends, and this preview is redrawn from that.
		var ds = section( 'Description' );
		var dtools = el( 'div', 'vh-review__desctools' );
		var desc = el( 'div', 'vh-review__desc' );
		desc.innerHTML = draft.description.html;

		if ( draft.description.edited ) {
			dtools.appendChild( el( 'span', 'vh-chip vh-chip--good', 'Edited by you' ) );
		}
		if ( draft.description.bytes ) {
			dtools.appendChild( el( 'span', 'vh-meta', Math.ceil( draft.description.bytes / 1024 ) + ' KB' ) );
		}

		var editBtn = el( 'button', 'vh-btn vh-btn--ghost vh-btn--sm', 'Edit description' );
		editBtn.type = 'button';
		dtools.appendChild( editBtn );

		if ( draft.description.edited ) {
			var resetBtn = el( 'button', 'vh-btn vh-btn--ghost vh-btn--sm', 'Use the generated description' );
			resetBtn.type = 'button';
			resetBtn.addEventListener( 'click', function () {
				delete request.description;
				loadDraft( d, request, true );
			} );
			dtools.appendChild( resetBtn );
		}

		var editor = el( 'div', 'vh-review__editor' );
		editor.hidden = true;
		var area = el( 'textarea', 'vh-review__textarea' );
		area.value = draft.description.text || '';
		area.rows = 16;
		area.setAttribute( 'aria-label', 'Description' );
		editor.appendChild( area );
		editor.appendChild( el( 'p', 'vh-meta', 'Blank line between paragraphs · ## Heading · - bullet · **bold** · `code` · [text](https://link) · --- for a line. Changing the due date afterwards does not rewrite your text.' ) );
		var eBar = el( 'div', 'vh-review__editbar' );
		var applyBtn = el( 'button', 'vh-btn vh-btn--primary vh-btn--sm', 'Apply to the ticket' );
		applyBtn.type = 'button';
		var cancelEdit = el( 'button', 'vh-btn vh-btn--ghost vh-btn--sm', 'Cancel' );
		cancelEdit.type = 'button';
		var count = el( 'span', 'vh-meta' );
		var recount = function () { count.textContent = area.value.length.toLocaleString() + ' characters'; };
		recount();
		area.addEventListener( 'input', recount );
		eBar.appendChild( applyBtn );
		eBar.appendChild( cancelEdit );
		eBar.appendChild( count );
		editor.appendChild( eBar );

		editBtn.addEventListener( 'click', function () {
			editor.hidden = false;
			desc.hidden = true;
			editBtn.hidden = true;
			area.focus();
		} );
		cancelEdit.addEventListener( 'click', function () {
			area.value = draft.description.text || '';
			recount();
			editor.hidden = true;
			desc.hidden = false;
			editBtn.hidden = false;
		} );
		applyBtn.addEventListener( 'click', function () {
			if ( ! area.value.trim() ) {
				delete request.description;
			} else {
				request.description = area.value;
			}
			loadDraft( d, request, true );
		} );

		ds.appendChild( dtools );
		ds.appendChild( desc );
		ds.appendChild( editor );
		body.appendChild( ds );

		// Attachment.
		var as = section( 'Attachment' );
		if ( draft.attachment ) {
			var a = draft.attachment;
			var meta = el( 'p', 'vh-review__att' );
			meta.appendChild( el( 'strong', null, a.name ) );
			meta.appendChild( document.createTextNode( ' · ' + a.rows + ' rows · ' + a.columns.length + ' columns · ' + a.size + ' · ' ) );
			var link = el( 'a', null, 'Download this exact file' );
			link.href = a.download;
			meta.appendChild( link );
			as.appendChild( meta );

			if ( draft.columns && draft.columns.length ) {
				var picker = el( 'details', 'vh-review__cols' );
				picker.appendChild( el( 'summary', null, 'Choose the columns in the file' ) );
				var grid = el( 'div', 'vh-export__cols' );
				var groups = {};
				draft.columns.forEach( function ( c ) {
					if ( ! groups[ c.group ] ) {
						groups[ c.group ] = el( 'fieldset', 'vh-export__group' );
						groups[ c.group ].appendChild( el( 'legend', null, c.group ) );
						grid.appendChild( groups[ c.group ] );
					}
					var lab = el( 'label' );
					var box = el( 'input' );
					box.type = 'checkbox';
					box.value = c.key;
					box.checked = !! c.checked;
					lab.appendChild( box );
					lab.appendChild( el( 'span', null, c.label ) );
					groups[ c.group ].appendChild( lab );
				} );
				picker.appendChild( grid );
				var redo = el( 'button', 'vh-btn vh-btn--sm', 'Rebuild the file with these columns' );
				redo.type = 'button';
				redo.addEventListener( 'click', function () {
					var cols = [];
					grid.querySelectorAll( 'input:checked' ).forEach( function ( b ) { cols.push( b.value ); } );
					request.cols = cols;
					loadDraft( d, request, true );
				} );
				picker.appendChild( redo );
				as.appendChild( picker );
			}

			var wrap = el( 'div', 'vh-review__tablewrap' );
			var table = el( 'table', 'vh-table vh-review__table' );
			var thead = el( 'thead' );
			var hr = el( 'tr' );
			( a.header || [] ).forEach( function ( h ) { hr.appendChild( el( 'th', null, h ) ); } );
			thead.appendChild( hr );
			table.appendChild( thead );
			var tb = el( 'tbody' );
			( a.preview || [] ).forEach( function ( row ) {
				var tr = el( 'tr' );
				row.forEach( function ( cell ) { tr.appendChild( el( 'td', null, cell ) ); } );
				tb.appendChild( tr );
			} );
			table.appendChild( tb );
			wrap.appendChild( table );
			as.appendChild( wrap );
			if ( a.rows > ( a.preview || [] ).length ) {
				as.appendChild( el( 'p', 'vh-sub', 'Showing the first ' + ( a.preview || [] ).length + ' of ' + a.rows + ' rows. Download the file to see every row.' ) );
			}
		} else {
			as.appendChild( el( 'p', 'vh-sub', 'No file will be attached.' ) );
		}
		body.appendChild( as );

		// Also sent, and the raw payload.
		var also = section( 'Also sent after the issue is created' );
		var ul = el( 'ul' );
		( draft.also || [] ).forEach( function ( t ) { ul.appendChild( el( 'li', null, t ) ); } );
		also.appendChild( ( draft.also || [] ).length ? ul : el( 'p', 'vh-sub', 'Nothing else: no links or other data are added after the issue and its attachment.' ) );
		var raw = el( 'details', 'vh-review__raw' );
		raw.appendChild( el( 'summary', null, 'Show the exact JSON sent to Jira' ) );
		raw.appendChild( el( 'pre', null, JSON.stringify( { fields: draft.payload }, null, 2 ) ) );
		also.appendChild( raw );
		body.appendChild( also );

		send.disabled = false;
		send.onclick = function () {
			send.disabled = true;
			status.textContent = 'Sending to Jira…';
			wp.apiFetch( { path: '/vulnhub/v1/tickets', method: 'POST', data: { draft: draft.token } } )
				.then( function ( result ) {
					status.textContent = '';
					body.innerHTML = '';
					body.appendChild( el( 'div', 'vh-notice vh-notice--good', result.message || 'Ticket created.' ) );
					send.textContent = result.redirect ? 'Open the ticket' : 'Close';
					send.disabled = false;
					send.onclick = function () {
						stopCountdown( d, '' );
						if ( result.redirect ) { window.location.href = result.redirect; } else { window.location.reload(); }
					};

					/* The lede still read "Nothing has been sent" above a
					   notice saying what had just been created. */
					var lede = d.querySelector( '.vh-review__lede' );
					if ( lede ) { lede.textContent = 'Sent. The ticket exists in Jira now.'; }

					countdownToClose( d, 5 );
				} )
				.catch( function ( error ) {
					status.textContent = '';
					body.insertBefore( el( 'div', 'vh-notice vh-notice--warn', ( error && error.message ) || cfg.i18n.error ), body.firstChild );
					// The draft is spent once a send is attempted; a new review is needed.
					send.textContent = 'Send to Jira';
					send.disabled = true;
				} );
		};
	}

	function loadDraft( d, request, rebuilding ) {
		var body = d.querySelector( '[data-vh-review-body]' );
		var send = d.querySelector( '[data-vh-review-send]' );

		// The dialog is reused, so a new review starts from the review state:
		// no timer left running, and the lede back to what is true again.
		stopCountdown( d, '' );
		var lede = d.querySelector( '.vh-review__lede' );
		if ( lede ) { lede.textContent = 'Nothing has been sent. This is exactly what will travel to Jira when you press Send.'; }

		send.disabled = true;
		send.textContent = 'Send to Jira';
		if ( ! rebuilding ) { body.innerHTML = ''; }
		d.querySelector( '[data-vh-review-status]' ).textContent = rebuilding ? 'Rebuilding the ticket…' : 'Building the ticket…';
		if ( ! d.open ) { d.showModal(); }

		return wp.apiFetch( { path: '/vulnhub/v1/tickets/draft', method: 'POST', data: request } )
			.then( function ( draft ) { renderDraft( d, draft, request ); } )
			.catch( function ( error ) { renderDraft( d, { ok: false, message: error && error.message }, request ); } );
	}

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '[data-vh-raise]' );
		if ( ! button ) {
			return;
		}
		event.preventDefault();

		var request = { cols: [] };

		if ( button.dataset.vhFinding ) {
			request.finding_ids = [ parseInt( button.dataset.vhFinding, 10 ) ];
		} else if ( 'all' === selMode ) {
			// "All N matching findings selected": send the screen's filters and
			// let the server resolve them, exactly as Export selected does.
			var form = document.querySelector( '.vh-export__panel' );
			request.all = 1;
			request.filters = {};
			if ( form ) {
				form.querySelectorAll( 'input[name]' ).forEach( function ( input ) {
					if ( 'cols[]' !== input.name ) { request.filters[ input.name ] = input.value; }
				} );
			}
		} else {
			request.finding_ids = [];
			document.querySelectorAll( '.vh-pick:checked' ).forEach( function ( box ) {
				request.finding_ids.push( parseInt( box.value, 10 ) );
			} );
			if ( ! request.finding_ids.length ) {
				toast( cfg.i18n.noSelect, 'warn' );
				return;
			}
		}

		loadDraft( reviewDialog(), request, false );
	} );

	/*
	 * Assets & owners: the Raise Jira ticket dialog's "Review and create in
	 * Jira". Carries the list's filters (f[...]), its raw query (q[...]), the
	 * request type, summary, notes and the columns ticked above, then hands
	 * over to the same review.
	 */
	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '[data-vh-raise-scope]' );
		if ( ! button ) {
			return;
		}
		event.preventDefault();

		var form = button.closest( 'form' );
		var request = { scope: 'assets', filters: {}, query: {}, cols: [] };

		form.querySelectorAll( 'input[type="hidden"]' ).forEach( function ( input ) {
			var m = /^([fq])\[([^\]]+)\]$/.exec( input.name );
			if ( m ) { ( 'f' === m[1] ? request.filters : request.query )[ m[2] ] = input.value; }
		} );
		form.querySelectorAll( 'input[name="cols[]"]:checked' ).forEach( function ( box ) { request.cols.push( box.value ); } );
		request.kind = ( form.querySelector( '[name="kind"]' ) || {} ).value || '';
		request.summary = ( form.querySelector( '[name="summary"]' ) || {} ).value || '';
		request.notes = ( form.querySelector( '[name="notes"]' ) || {} ).value || '';

		var host = button.closest( 'dialog' );
		if ( host && host.open ) { host.close(); }

		loadDraft( reviewDialog(), request, false );
	} );
}() );


/* ===================================================================== *
 * Dashboard: the widget editor, and exporting a widget.
 *
 * The editor is progressive. Without this file the dashboard still renders
 * from the saved layout; you simply cannot rearrange it, and the Customise
 * button stays hidden.
 * ===================================================================== */
( function () {
	'use strict';

	var form   = document.getElementById( 'vh-customise' );
	var toggle = document.querySelector( '[data-vh-customise]' );

	/* ------------------------------------------------------------ editor. */
	if ( form && toggle ) {
		var picked = form.querySelector( '[data-vh-picked]' );
		var empty  = form.querySelector( '[data-vh-picked-empty]' );
		var field  = form.querySelector( '[data-vh-layout-field]' );

		toggle.hidden = false;

		toggle.addEventListener( 'click', function () {
			var open = form.hasAttribute( 'hidden' );
			if ( open ) {
				form.removeAttribute( 'hidden' );
			} else {
				form.setAttribute( 'hidden', '' );
			}
			toggle.setAttribute( 'aria-expanded', open ? 'true' : 'false' );
			if ( open ) {
				form.scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
			}
		} );

		function widths() {
			var sel = picked.querySelector( '[data-vh-width-select]' );
			return sel ? Array.prototype.map.call( sel.options, function ( o ) { return o.value; } ) : [ '3', '4', '6', '8', '12' ];
		}

		function refresh() {
			var ids = [];
			Array.prototype.forEach.call( picked.children, function ( li ) {
				ids.push( li.getAttribute( 'data-vh-id' ) );
			} );

			// An already-placed widget cannot be added twice.
			Array.prototype.forEach.call( form.querySelectorAll( '[data-vh-add]' ), function ( btn ) {
				btn.disabled = ids.indexOf( btn.getAttribute( 'data-vh-add' ) ) !== -1;
			} );

			if ( empty ) {
				empty.hidden = ids.length > 0;
			}

			var layout = [];
			Array.prototype.forEach.call( picked.children, function ( li ) {
				var sel = li.querySelector( '[data-vh-width-select]' );
				layout.push( {
					id: li.getAttribute( 'data-vh-id' ),
					width: parseInt( sel ? sel.value : li.getAttribute( 'data-vh-width' ), 10 )
				} );
			} );
			field.value = JSON.stringify( layout );
		}

		function makeRow( id, label, width ) {
			var li = document.createElement( 'li' );
			li.className = 'vh-picked__row';
			li.setAttribute( 'draggable', 'true' );
			li.setAttribute( 'data-vh-id', id );
			li.setAttribute( 'data-vh-width', width );

			var opts = widths().map( function ( w ) {
				return '<option value="' + w + '"' + ( String( w ) === String( width ) ? ' selected' : '' ) + '>' + w + '/12</option>';
			} ).join( '' );

			li.innerHTML =
				'<span class="vh-picked__grip" aria-hidden="true">⋮⋮</span>' +
				'<span class="vh-picked__label"></span>' +
				'<label class="vh-picked__width"><select data-vh-width-select>' + opts + '</select></label>' +
				'<button type="button" class="vh-picked__remove" data-vh-remove aria-label="Remove widget">×</button>';

			li.querySelector( '.vh-picked__label' ).textContent = label;
			bindDrag( li );
			return li;
		}

		form.addEventListener( 'click', function ( e ) {
			var add = e.target.closest( '[data-vh-add]' );
			if ( add && ! add.disabled ) {
				picked.appendChild(
					makeRow(
						add.getAttribute( 'data-vh-add' ),
						add.getAttribute( 'data-vh-label' ),
						add.getAttribute( 'data-vh-default-width' )
					)
				);
				refresh();
				return;
			}

			var remove = e.target.closest( '[data-vh-remove]' );
			if ( remove ) {
				remove.closest( '.vh-picked__row' ).remove();
				refresh();
			}
		} );

		form.addEventListener( 'change', function ( e ) {
			if ( e.target.matches( '[data-vh-width-select]' ) ) {
				refresh();
			}
		} );

		// Reorder. Plain HTML drag and drop -- no library, and the list is
		// still usable with a keyboard because order can be rebuilt by
		// removing and re-adding.
		var dragging = null;

		function bindDrag( li ) {
			li.addEventListener( 'dragstart', function ( e ) {
				dragging = li;
				li.classList.add( 'is-dragging' );
				e.dataTransfer.effectAllowed = 'move';
				try { e.dataTransfer.setData( 'text/plain', li.getAttribute( 'data-vh-id' ) ); } catch ( err ) {}
			} );
			li.addEventListener( 'dragend', function () {
				dragging = null;
				li.classList.remove( 'is-dragging' );
				Array.prototype.forEach.call( picked.children, function ( r ) { r.classList.remove( 'is-over' ); } );
				refresh();
			} );
			li.addEventListener( 'dragover', function ( e ) {
				if ( ! dragging || dragging === li ) { return; }
				e.preventDefault();
				li.classList.add( 'is-over' );
			} );
			li.addEventListener( 'dragleave', function () { li.classList.remove( 'is-over' ); } );
			li.addEventListener( 'drop', function ( e ) {
				if ( ! dragging || dragging === li ) { return; }
				e.preventDefault();
				li.classList.remove( 'is-over' );
				var rows = Array.prototype.slice.call( picked.children );
				picked.insertBefore( dragging, rows.indexOf( dragging ) < rows.indexOf( li ) ? li.nextSibling : li );
				refresh();
			} );
		}

		Array.prototype.forEach.call( picked.children, bindDrag );
		refresh();
	}

	/* ============================================================ board. *
	 *
	 * Two jobs: pack the grid so there are no holes, and let somebody move a
	 * widget where they want it and have that stick.
	 * ==================================================================== */

	var board = document.querySelector( '[data-vh-board]' );

	if ( board ) {
		var ROW = 8;            // px per grid row track; smaller = finer packing.
		var GAP = 16;           // must match the board's `gap` in app.css.
		var packTimer = null;
		var saveTimer = null;
		var statusEl = null;
		var live = null;

		/* ------------------------------------------------------- packing. */

		/**
		 * Give every widget a row span matching its measured height.
		 *
		 * Grid makes each item in a row as tall as the tallest, so a short
		 * widget beside a tall one leaves a void beneath it. Against a fine
		 * row track, an explicit span lets the next widget start immediately
		 * under the short one instead -- masonry, until the real thing ships.
		 */
		function pack() {
			var items = board.querySelectorAll( '.vh-w' );

			if ( ! items.length ) { return; }

			/*
			 * Measure from the content, with every trace of the last pass
			 * removed first.
			 *
			 * Dropping `is-packed` alone was not enough: the inline
			 * `grid-row-end: span 35` from the previous run stayed on the
			 * element, and without the 8px row track it meant 35 *auto* rows.
			 * Widgets measured tens of thousands of pixels tall, the spans
			 * computed from that were astronomical, and the board ran to
			 * eleven million pixels. Clear the inline styles, then measure.
			 */
			board.classList.remove( 'is-packed' );

			for ( var c = 0; c < items.length; c++ ) {
				items[ c ].style.gridRowEnd = '';
				items[ c ].style.alignSelf = '';
			}

			var heights = [];
			for ( var i = 0; i < items.length; i++ ) {
				heights.push( items[ i ].getBoundingClientRect().height );
			}

			// One column means one widget per row, and spans buy nothing.
			if ( window.matchMedia( '(max-width: 900px)' ).matches ) { return; }

			board.style.setProperty( '--vh-board-unit', ROW + 'px' );
			board.classList.add( 'is-packed' );

			var spans = [];

			for ( var j = 0; j < items.length; j++ ) {
				spans[ j ] = Math.max( 1, Math.ceil( ( heights[ j ] + GAP ) / ( ROW + GAP ) ) );
				items[ j ].style.alignSelf = '';
				items[ j ].style.gridRowEnd = 'span ' + spans[ j ];
			}

			/*
			 * Second pass: close the one hole packing cannot.
			 *
			 * A full-width widget has to clear every column, so a short widget
			 * beside a tall one in the band above it leaves a gap nothing can
			 * backfill -- and reshuffling is not on the table, because the
			 * order is the operator's. The short card grows into the space
			 * instead.
			 *
			 * Only that case. A full-width widget's top is already fixed by
			 * the tallest card above it, so stretching its shorter neighbours
			 * down to meet it cannot move anything -- there is no feedback.
			 * Doing this for arbitrary neighbours does feed back: an earlier
			 * attempt stretched a card, which pushed the next one down, which
			 * opened a bigger hole, which stretched further, and the board
			 * grew to ten thousand pixels of mostly padding.
			 */
			var base = board.getBoundingClientRect();
			var boxes = [];

			for ( var k = 0; k < items.length; k++ ) {
				var b = items[ k ].getBoundingClientRect();
				boxes[ k ] = {
					full: '12' === items[ k ].getAttribute( 'data-vh-width' ),
					left: b.left - base.left,
					right: b.right - base.left,
					top: b.top - base.top,
					bottom: b.bottom - base.top
				};
			}

			for ( var m = 0; m < items.length; m++ ) {
				var me = boxes[ m ];
				var below = null;

				for ( var n = 0; n < items.length; n++ ) {
					if ( n === m ) { continue; }

					var other = boxes[ n ];

					if ( other.top >= me.bottom - 1 && other.left < me.right - 1 && other.right > me.left + 1 ) {
						if ( ! below || other.top < below.top ) { below = other; }
					}
				}

				if ( ! below || ! below.full ) { continue; }

				var hole = below.top - me.bottom - GAP;

				if ( hole <= ROW ) { continue; }

				// A sanity bound. Closing a gap should never more than double
				// a card; anything larger means the measurement was wrong, and
				// a gap is a far better outcome than a mile of blank panel.
				var extra = Math.min( spans[ m ], Math.floor( hole / ( ROW + GAP ) ) );

				items[ m ].style.gridRowEnd = 'span ' + ( spans[ m ] + extra );
				items[ m ].style.alignSelf = 'stretch';
			}
		}

		function repack() {
			window.clearTimeout( packTimer );
			packTimer = window.setTimeout( pack, 60 );
		}

		/**
		 * Drop the packing immediately, then re-derive it at leisure.
		 *
		 * The spans are computed for a particular column count. Keeping them
		 * for the 60ms the debounce takes leaves desktop spans applied to a
		 * phone-width board, which measured as a few pixels of horizontal
		 * overflow if anything looked in that window. Cheap to undo, so undo
		 * it now and recompute after.
		 */
		function unpack() {
			board.classList.remove( 'is-packed' );

			var items = board.querySelectorAll( '.vh-w' );

			for ( var i = 0; i < items.length; i++ ) {
				items[ i ].style.gridRowEnd = '';
				items[ i ].style.alignSelf = '';
			}
		}

		// Anything that changes a widget's height changes its span: opening a
		// table view, a chart re-rendering, the window resizing, a font
		// arriving late.
		window.addEventListener( 'resize', function () {
			unpack();
			repack();
		} );
		board.addEventListener( 'toggle', repack, true );

		if ( window.ResizeObserver ) {
			var ro = new ResizeObserver( repack );
			Array.prototype.forEach.call( board.querySelectorAll( '.vh-w__body' ), function ( b ) {
				ro.observe( b );
			} );
		}

		if ( document.fonts && document.fonts.ready ) {
			document.fonts.ready.then( repack );
		}

		pack();

		/* -------------------------------------------------------- saving. */

		function status( message, bad ) {
			if ( ! statusEl ) {
				statusEl = document.createElement( 'div' );
				statusEl.className = 'vh-board__status';
				statusEl.setAttribute( 'role', 'status' );
				document.body.appendChild( statusEl );
			}

			statusEl.textContent = message;
			statusEl.classList.toggle( 'vh-board__status--bad', !! bad );
			statusEl.classList.add( 'is-visible' );

			window.clearTimeout( statusEl.timer );
			statusEl.timer = window.setTimeout( function () {
				statusEl.classList.remove( 'is-visible' );
			}, bad ? 6000 : 2000 );
		}

		function currentLayout() {
			return Array.prototype.map.call( board.querySelectorAll( '.vh-w' ), function ( w ) {
				return {
					id: w.getAttribute( 'data-vh-widget' ),
					width: parseInt( w.getAttribute( 'data-vh-width' ), 10 ) || 12
				};
			} );
		}

		var pending = false;

		/**
		 * @param {boolean} leaving True when the page is going away, in which
		 *                          case the request must survive it.
		 */
		function send( leaving ) {
			var cfg = window.VulnHubApp || {};

			pending = false;

			return fetch( ( cfg.restRoot || '/wp-json/vulnhub-dashboard/v1/' ) + 'layout', {
				method: 'POST',
				credentials: 'same-origin',
				// keepalive lets the request outlive the document, which is
				// what makes the pagehide flush below actually arrive.
				keepalive: !! leaving,
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': cfg.nonce || ''
				},
				body: JSON.stringify( { layout: currentLayout() } )
			} ).then( function ( r ) {
				if ( ! r.ok ) { throw new Error( 'save failed' ); }
				return r.json();
			} ).then( function () {
				if ( ! leaving ) {
					status( ( cfg.i18n && cfg.i18n.layoutSaved ) || 'Layout saved' );
				}
			} ).catch( function () {
				if ( ! leaving ) {
					status(
						( cfg.i18n && cfg.i18n.layoutFailed ) || 'Could not save that arrangement',
						true
					);
				}
			} );
		}

		/**
		 * Debounced, because moving three widgets is one intention, not three.
		 */
		function save() {
			pending = true;
			window.clearTimeout( saveTimer );
			saveTimer = window.setTimeout( function () { send( false ); }, 400 );
		}

		/*
		 * Nudge a widget and immediately click away and the debounce would
		 * still be counting when the document went. Flush it on the way out.
		 */
		window.addEventListener( 'pagehide', function () {
			if ( ! pending ) { return; }
			window.clearTimeout( saveTimer );
			send( true );
		} );

		document.addEventListener( 'visibilitychange', function () {
			if ( 'hidden' === document.visibilityState && pending ) {
				window.clearTimeout( saveTimer );
				send( true );
			}
		} );

		/* ---------------------------------------------------- announcing. */

		function announce( message ) {
			if ( ! live ) {
				live = document.createElement( 'p' );
				live.className = 'vh-visually-hidden';
				live.setAttribute( 'aria-live', 'polite' );
				board.parentNode.insertBefore( live, board );
			}
			live.textContent = message;
		}

		function positionOf( widget ) {
			return Array.prototype.indexOf.call( board.querySelectorAll( '.vh-w' ), widget ) + 1;
		}

		function moved( widget ) {
			widget.classList.remove( 'is-moved' );
			// Force a reflow so the animation restarts on a second move.
			void widget.offsetWidth;
			widget.classList.add( 'is-moved' );

			repack();
			save();

			var label = widget.getAttribute( 'aria-label' ) || '';
			announce( label + ' — position ' + positionOf( widget ) + ' of ' + board.querySelectorAll( '.vh-w' ).length );
		}

		/* --------------------------------------------------------- drag. *
		 *
		 * Pointer events, not HTML5 drag and drop. Two reasons: HTML5 dragging
		 * does not exist on a touch screen at all, and it only ever shows a
		 * ghost image -- the board underneath does not move until you let go.
		 * Tracking the pointer ourselves means the widgets reflow around the
		 * one being carried, which is the whole point of moving it.
		 */

		var carrying  = null;   // the widget being carried
		var ghost     = null;   // the gap it will drop into
		var pointerId = null;
		var startX = 0, startY = 0;   // where the press began
		var grabDX = 0, grabDY = 0;   // where inside the widget it was grabbed
		var lastX  = 0, lastY  = 0;   // latest pointer position, viewport coords
		var armed  = false;
		var loop   = null;

		var EDGE  = 96;   // px from a viewport edge where auto-scroll starts
		var SPEED = 26;   // px per frame at the very edge

		function reduced() {
			return !! ( window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches );
		}

		function widgetOf( node ) {
			return node && node.closest ? node.closest( '.vh-w' ) : null;
		}

		/**
		 * The widget under the pointer.
		 *
		 * The carried widget is out of the board and `pointer-events: none`,
		 * so it cannot be its own answer -- but the guard stays because a
		 * mid-flight drop puts it back and this can run one more frame.
		 */
		function widgetUnder( x, y ) {
			var w = widgetOf( document.elementFromPoint( x, y ) );

			return w && w !== carrying && board.contains( w ) ? w : null;
		}

		/**
		 * Lift the widget out of the grid and on to the pointer.
		 *
		 * Two things have to happen at once for this to read as picking
		 * something up: the widget starts following the cursor, and the space
		 * it came from stays open so you can see where it will land. So the
		 * widget goes to `position: fixed` and a ghost of exactly its
		 * footprint takes its place in the grid.
		 *
		 * It is re-parented to <body>, not left where it was. `.vh-main`
		 * carries a transform, which makes it the containing block for fixed
		 * positioning -- the same trap that put the export popover at y=961
		 * in a 900px window. Against <body> the coordinates are the viewport's
		 * and the arithmetic is simply the pointer position.
		 */
		function lift( e ) {
			var box = carrying.getBoundingClientRect();
			var cs  = window.getComputedStyle( carrying );

			grabDX = startX - box.left;
			grabDY = startY - box.top;

			ghost = document.createElement( 'div' );
			ghost.className = 'vh-w-ghost';
			ghost.setAttribute( 'aria-hidden', 'true' );
			/*
			 * Deliberately NOT class `vh-w`, and with no `data-vh-widget`:
			 * currentLayout() maps over `.vh-w` to build what gets saved, and
			 * a ghost in that list would post a layout with a phantom widget
			 * in it.
			 */
			ghost.style.gridColumn = cs.gridColumn;
			ghost.style.gridRowEnd = carrying.style.gridRowEnd || '';
			ghost.style.height     = box.height + 'px';

			board.insertBefore( ghost, carrying );

			carrying.style.width  = box.width + 'px';
			carrying.style.height = box.height + 'px';
			carrying.style.left   = '0';
			carrying.style.top    = '0';
			carrying.classList.add( 'is-dragging' );
			document.body.appendChild( carrying );
			document.body.classList.add( 'vh-is-dragging' );
			board.classList.add( 'is-arranging' );

			paint();
		}

		/** Put the carried widget where the pointer is. */
		function paint() {
			if ( ! carrying ) { return; }
			carrying.style.transform = 'translate3d(' + ( lastX - grabDX ) + 'px,' + ( lastY - grabDY ) + 'px,0)';
		}

		/** Move the gap to wherever the pointer is now pointing. */
		function placeGhost() {
			var over = widgetUnder( lastX, lastY );

			if ( ! over || ! ghost ) { return; }

			var box   = over.getBoundingClientRect();
			var after = ( lastY - box.top ) > box.height / 2;

			if ( after ) {
				if ( over.nextSibling !== ghost ) { board.insertBefore( ghost, over.nextSibling ); }
			} else if ( over.previousSibling !== ghost ) {
				board.insertBefore( ghost, over );
			}
		}

		/**
		 * Scroll the page when the pointer nears an edge, and keep painting.
		 *
		 * This runs every frame rather than off pointermove, because the two
		 * moments that matter most have no pointer movement in them at all:
		 * holding still at the bottom of the window waiting for the page to
		 * come to you, and the drop target changing underneath a stationary
		 * cursor while it does.
		 */
		function tick() {
			loop = null;

			if ( ! carrying || ! armed ) { return; }

			var h  = window.innerHeight;
			var vy = 0;

			if ( lastY < EDGE ) {
				vy = -SPEED * ( 1 - lastY / EDGE );
			} else if ( lastY > h - EDGE ) {
				vy = SPEED * ( 1 - ( h - lastY ) / EDGE );
			}

			if ( vy ) { window.scrollBy( 0, vy ); }

			paint();
			placeGhost();

			loop = window.requestAnimationFrame( tick );
		}

		/**
		 * Drop it, and let it fly home rather than teleport.
		 *
		 * The widget is put back in the DOM first and only then animated from
		 * where the hand left it to where the grid actually put it (a FLIP).
		 * Animating to a guessed position and then swapping would show a
		 * one-frame jump whenever packing changed the answer.
		 */
		function endCarry() {
			if ( ! carrying ) { return; }

			var widget = carrying;
			var wasArmed = armed;
			var from = wasArmed ? widget.getBoundingClientRect() : null;

			window.cancelAnimationFrame( loop );
			loop = null;

			if ( ghost ) {
				board.insertBefore( widget, ghost );
				ghost.parentNode.removeChild( ghost );
				ghost = null;
			}

			widget.classList.remove( 'is-dragging' );
			widget.style.width = widget.style.height = '';
			widget.style.left = widget.style.top = widget.style.transform = '';
			document.body.classList.remove( 'vh-is-dragging' );
			board.classList.remove( 'is-arranging' );

			carrying  = null;
			pointerId = null;
			armed     = false;

			if ( ! wasArmed ) { return; }

			if ( ! reduced() ) {
				var to = widget.getBoundingClientRect();
				var dx = from.left - to.left;
				var dy = from.top - to.top;

				if ( dx || dy ) {
					/*
					 * `animation: none` for the same reason the dragging rule
					 * needs it: vhIn's filled final keyframe is
					 * `transform: none`, and it outranks this inline
					 * transform, so the widget would simply not move.
					 */
					widget.style.animation  = 'none';
					widget.style.transition = 'none';
					widget.style.transform  = 'translate3d(' + dx + 'px,' + dy + 'px,0)';

					window.requestAnimationFrame( function () {
						widget.style.transition = 'transform .22s cubic-bezier(.2,.8,.3,1)';
						widget.style.transform  = '';

						window.setTimeout( function () {
							widget.style.transition = '';
							widget.style.animation  = '';
						}, 260 );
					} );
				}
			}

			moved( widget );
		}

		/*
		 * The pointer is tracked on the document, not on the grip.
		 *
		 * `setPointerCapture` looked like the right tool and quietly was not:
		 * carrying re-parents the widget -- and the grip inside it -- and
		 * re-parenting an element releases its capture. So after the first
		 * move the grip stopped hearing the pointer, the drop was never
		 * committed and nothing was saved. Document-level listeners have no
		 * such attachment to the node being moved.
		 */
		Array.prototype.forEach.call( board.querySelectorAll( '[data-vh-grip]' ), function ( grip ) {
			var widget = widgetOf( grip );

			if ( ! widget ) { return; }

			grip.hidden = false;

			grip.addEventListener( 'pointerdown', function ( e ) {
				if ( e.button !== 0 ) { return; }

				carrying  = widget;
				pointerId = e.pointerId;
				startX = lastX = e.clientX;
				startY = lastY = e.clientY;
				armed  = false;

				// Stops the press turning into a text selection or a scroll.
				e.preventDefault();
			} );

			grip.addEventListener( 'keydown', function ( e ) {
				var items = Array.prototype.slice.call( board.querySelectorAll( '.vh-w' ) );
				var at = items.indexOf( widget );
				var to = at;

				if ( 'ArrowLeft' === e.key || 'ArrowUp' === e.key ) { to = at - 1; }
				else if ( 'ArrowRight' === e.key || 'ArrowDown' === e.key ) { to = at + 1; }
				else if ( 'Home' === e.key ) { to = 0; }
				else if ( 'End' === e.key ) { to = items.length - 1; }
				else { return; }

				e.preventDefault();

				if ( to < 0 || to >= items.length || to === at ) { return; }

				if ( to > at ) {
					board.insertBefore( widget, items[ to ].nextSibling );
				} else {
					board.insertBefore( widget, items[ to ] );
				}

				grip.focus();
				moved( widget );
			} );
		} );

		document.addEventListener( 'pointermove', function ( e ) {
			if ( ! carrying || e.pointerId !== pointerId ) { return; }

			lastX = e.clientX;
			lastY = e.clientY;

			if ( ! armed ) {
				// A few pixels of slop, so a click on the grip is not a
				// one-pixel drag that reorders the board by accident.
				if ( Math.abs( lastX - startX ) < 5 && Math.abs( lastY - startY ) < 5 ) {
					return;
				}

				armed = true;
				lift( e );
				loop = window.requestAnimationFrame( tick );
			}

			e.preventDefault();
		} );

		document.addEventListener( 'pointerup', endCarry );
		document.addEventListener( 'pointercancel', endCarry );
		// A drag that ends outside the window still has to be committed.
		window.addEventListener( 'blur', endCarry );

		// Escape drops it where it was picked up rather than where it hovers.
		document.addEventListener( 'keydown', function ( e ) {
			if ( 'Escape' === e.key && carrying ) { endCarry(); }
		} );
	}

	/* ------------------------------------------------------------ export. */

	/**
	 * Copy the computed paint back on to a cloned SVG.
	 *
	 * The charts are drawn with `var(--vh-...)`, which resolves against the
	 * page. Lift a chart out of the page and every one of those becomes
	 * black, so resolve them before serialising.
	 */
	function inlineStyles( source, clone ) {
		var from = source.querySelectorAll( '*' );
		var to   = clone.querySelectorAll( '*' );

		for ( var i = 0; i < from.length; i++ ) {
			var cs = window.getComputedStyle( from[ i ] );
			var el = to[ i ];
			[ 'fill', 'stroke', 'stroke-width', 'font-size', 'font-family', 'font-weight', 'opacity', 'text-anchor' ].forEach( function ( prop ) {
				var v = cs.getPropertyValue( prop );
				if ( v ) { el.style.setProperty( prop, v ); }
			} );
		}

		var root = window.getComputedStyle( document.body );
		clone.style.background = root.backgroundColor;
	}

	function serialise( svg ) {
		var clone = svg.cloneNode( true );
		inlineStyles( svg, clone );

		var box = svg.getBoundingClientRect();
		clone.setAttribute( 'xmlns', 'http://www.w3.org/2000/svg' );
		clone.setAttribute( 'width', Math.max( 1, Math.round( box.width ) ) );
		clone.setAttribute( 'height', Math.max( 1, Math.round( box.height ) ) );

		return new XMLSerializer().serializeToString( clone );
	}

	function download( blob, name ) {
		var url = URL.createObjectURL( blob );
		var a   = document.createElement( 'a' );
		a.href = url;
		a.download = name;
		document.body.appendChild( a );
		a.click();
		a.remove();
		setTimeout( function () { URL.revokeObjectURL( url ); }, 2000 );
	}

	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest( '[data-vh-export]' );
		if ( ! btn ) { return; }

		var widget = btn.closest( '[data-vh-widget]' );
		var svg    = widget && widget.querySelector( 'svg.vh-chart' );
		var name   = widget ? widget.getAttribute( 'data-vh-widget' ) : 'chart';

		if ( ! svg ) {
			window.alert( 'This widget has no chart to export. Use Download CSV for its data.' );
			return;
		}

		var markup = serialise( svg );

		if ( 'svg' === btn.getAttribute( 'data-vh-export' ) ) {
			download( new Blob( [ markup ], { type: 'image/svg+xml;charset=utf-8' } ), 'vulnhub-' + name + '.svg' );
			return;
		}

		var box   = svg.getBoundingClientRect();
		var scale = 2; // Retina, and legible when pasted into a deck.
		var canvas = document.createElement( 'canvas' );
		canvas.width  = Math.max( 1, Math.round( box.width * scale ) );
		canvas.height = Math.max( 1, Math.round( box.height * scale ) );

		var ctx = canvas.getContext( '2d' );
		ctx.fillStyle = window.getComputedStyle( document.body ).backgroundColor || '#fff';
		ctx.fillRect( 0, 0, canvas.width, canvas.height );

		var img = new Image();
		img.onload = function () {
			ctx.drawImage( img, 0, 0, canvas.width, canvas.height );
			canvas.toBlob( function ( blob ) {
				if ( blob ) { download( blob, 'vulnhub-' + name + '.png' ); }
			}, 'image/png' );
		};
		img.onerror = function () {
			window.alert( 'Could not render that chart to PNG. The SVG download works.' );
		};
		img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent( markup );
	} );

	// One export menu open at a time.
	document.addEventListener( 'click', function ( e ) {
		document.querySelectorAll( '.vh-w__menu[open]' ).forEach( function ( d ) {
			if ( ! d.contains( e.target ) ) { d.removeAttribute( 'open' ); }
		} );
	} );
}() );

/* ------------------------------------------------ copy a table out. */
/*
 * Two buttons, two audiences. "Copy table" puts real HTML on the clipboard
 * so it lands in an email or a Word report as a table; "Copy as TSV" puts
 * tab-separated text so it lands in a spreadsheet as cells. Pasting HTML
 * into Excel gives you one merged mess, and pasting TSV into an email gives
 * you a wall of text, so neither one alone is enough.
 */
( function () {
	'use strict';

	function cells( row ) {
		return Array.prototype.map.call( row.querySelectorAll( 'th, td' ), function ( cell ) {
			var big = cell.querySelector( '.vh-matrix__n' );
			var sub = cell.querySelector( '.vh-matrix__sub' );

			if ( big ) {
				// The findings count belongs in its own column once the
				// numbers are leaving the page and losing their layout.
				return [ big.textContent.trim(), sub ? sub.textContent.replace( /[^0-9,]/g, '' ).trim() : '' ];
			}

			return [ cell.textContent.replace( /\s+/g, ' ' ).trim() ];
		} ).reduce( function ( out, part ) {
			return out.concat( part );
		}, [] );
	}

	function grid( table ) {
		return Array.prototype.map.call( table.querySelectorAll( 'tr' ), cells ).filter( function ( row ) {
			return row.length;
		} );
	}

	function tsv( table ) {
		return grid( table ).map( function ( row ) {
			return row.join( '\t' );
		} ).join( '\n' );
	}

	function html( table ) {
		return '<table border="1" cellspacing="0" cellpadding="6">' + grid( table ).map( function ( row, i ) {
			var tag = 0 === i ? 'th' : 'td';
			return '<tr>' + row.map( function ( cell ) {
				return '<' + tag + '>' + cell.replace( /&/g, '&amp;' ).replace( /</g, '&lt;' ) + '</' + tag + '>';
			} ).join( '' ) + '</tr>';
		} ).join( '' ) + '</table>';
	}

	function flash( button, message ) {
		var original = button.getAttribute( 'data-vh-label' ) || button.textContent;
		button.setAttribute( 'data-vh-label', original );
		button.textContent = message;
		window.setTimeout( function () {
			button.textContent = original;
		}, 1600 );
	}

	function write( button, table, mode ) {
		var text = tsv( table );

		// Rich HTML needs the async clipboard API and a secure context. Where
		// that is missing -- an http:// staging host, an older browser -- the
		// plain text still works, which is the half that matters.
		if ( 'tsv' !== mode && window.ClipboardItem && navigator.clipboard && navigator.clipboard.write ) {
			navigator.clipboard.write( [
				new window.ClipboardItem( {
					'text/html': new Blob( [ html( table ) ], { type: 'text/html' } ),
					'text/plain': new Blob( [ text ], { type: 'text/plain' } )
				} )
			] ).then( function () {
				flash( button, 'Copied' );
			} ).catch( function () {
				legacy( button, text );
			} );
			return;
		}

		if ( navigator.clipboard && navigator.clipboard.writeText ) {
			navigator.clipboard.writeText( text ).then( function () {
				flash( button, 'Copied' );
			} ).catch( function () {
				legacy( button, text );
			} );
			return;
		}

		legacy( button, text );
	}

	function legacy( button, text ) {
		var box = document.createElement( 'textarea' );
		box.value = text;
		box.setAttribute( 'readonly', 'readonly' );
		box.style.position = 'fixed';
		box.style.opacity = '0';
		document.body.appendChild( box );
		box.select();

		try {
			document.execCommand( 'copy' );
			flash( button, 'Copied' );
		} catch ( e ) {
			flash( button, 'Press Ctrl+C' );
		}

		document.body.removeChild( box );
	}

	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest( '[data-vh-copy]' );

		if ( ! button ) {
			return;
		}

		// The matrix owns its own buttons; a widget's export menu sits in the
		// header, outside the body, so fall back to the whole widget.
		var wrap = button.closest( '[data-vh-matrix]' ) || button.closest( '[data-vh-widget]' );
		var table = wrap ? wrap.querySelector( 'table' ) : null;

		if ( ! table ) {
			return;
		}

		event.preventDefault();
		write( button, table, button.getAttribute( 'data-vh-copy' ) );
	} );
}() );

/* ------------------------------------------------------------ bulk select.
 *
 * Progressive: with JavaScript off the checkboxes and the buttons still post
 * and the server still does the right thing. All this adds is the running
 * count, select-all, and a confirmation before something that moves a lot of
 * numbers at once.
 */
( function () {
	'use strict';

	var form = document.querySelector( '[data-vh-bulk]' );

	if ( ! form ) {
		return;
	}

	var ticks = function () {
		return Array.prototype.slice.call( form.querySelectorAll( '[data-vh-tick]' ) );
	};

	var count = function () {
		return ticks().filter( function ( t ) { return t.checked; } ).length;
	};

	var sync = function () {
		var n     = count();
		var out   = form.querySelector( '[data-vh-tick-count]' );
		var all   = form.querySelector( '[data-vh-tick-all]' );
		var boxes = ticks();

		if ( out ) {
			out.textContent = String( n );
		}

		if ( all ) {
			all.checked       = n > 0 && n === boxes.length;
			all.indeterminate = n > 0 && n < boxes.length;
		}

		Array.prototype.forEach.call(
			form.querySelectorAll( '[data-vh-bulk-submit]' ),
			function ( b ) { b.disabled = 0 === n; }
		);
	};

	form.addEventListener( 'change', function ( e ) {
		var t = e.target;

		if ( t && t.hasAttribute && t.hasAttribute( 'data-vh-tick-all' ) ) {
			ticks().forEach( function ( box ) { box.checked = t.checked; } );
		}

		sync();
	} );

	sync();
} )();

/* A confirmation on anything that says it wants one, wherever it lives --
 * the bulk bar, or the single-asset form on the detail page. */
document.addEventListener( 'click', function ( e ) {
	var btn = e.target && e.target.closest ? e.target.closest( '[data-vh-confirm]' ) : null;

	if ( ! btn ) {
		return;
	}

	if ( ! window.confirm( btn.getAttribute( 'data-vh-confirm' ) ) ) {
		e.preventDefault();
	}
} );


/* ===================================================================== *
 * Vendors: drill-down modal.
 *
 * Each stat on a vendor card (assets, products, findings, critical,
 * uncovered, archived) is an <a> whose href is the CSV export of that list.
 * With scripting off the link just downloads the CSV. Here we intercept it,
 * open a modal, and load the list from the REST endpoint with server-side
 * search, a scope/severity filter and pagination — the same rows the CSV
 * holds, so the popup and the download can never disagree.
 * ===================================================================== */
( function () {
	'use strict';

	if ( ! window.wp || ! wp.apiFetch ) {
		return; // no apiFetch: the plain CSV links still work.
	}

	var cfg = window.VulnHubApp || { i18n: {} };
	var overlay, panel, state = null, searchTimer = null;

	function esc( v ) { return v == null ? '' : String( v ); }

	function build() {
		overlay = document.createElement( 'div' );
		overlay.className = 'vh-modal';
		overlay.setAttribute( 'hidden', '' );
		overlay.innerHTML =
			'<div class="vh-modal__panel" role="dialog" aria-modal="true" aria-labelledby="vh-modal-title" tabindex="-1">' +
				'<header class="vh-modal__head">' +
					'<div><h2 id="vh-modal-title" class="vh-modal__title"></h2>' +
					'<p class="vh-modal__sub"></p></div>' +
					'<button type="button" class="vh-modal__close" aria-label="Close">&times;</button>' +
				'</header>' +
				'<div class="vh-modal__tools">' +
					'<input type="search" class="vh-modal__search" placeholder="Search…" autocomplete="off">' +
					'<select class="vh-modal__filter" hidden></select>' +
					'<a class="vh-btn vh-btn--ghost vh-btn--sm vh-modal__export" target="_blank" rel="noopener">Export CSV</a>' +
				'</div>' +
				'<div class="vh-modal__body"><div class="vh-modal__loading">Loading…</div></div>' +
				'<footer class="vh-modal__foot">' +
					'<span class="vh-modal__count"></span>' +
					'<span class="vh-modal__pager">' +
						'<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-prev>Prev</button>' +
						'<span class="vh-modal__page"></span>' +
						'<button type="button" class="vh-btn vh-btn--ghost vh-btn--sm" data-vh-next>Next</button>' +
					'</span>' +
				'</footer>' +
			'</div>';
		document.body.appendChild( overlay );
		panel = overlay.querySelector( '.vh-modal__panel' );

		overlay.addEventListener( 'click', function ( e ) {
			if ( e.target === overlay || e.target.closest( '.vh-modal__close' ) ) { close(); }
		} );
		document.addEventListener( 'keydown', function ( e ) {
			if ( e.key === 'Escape' && ! overlay.hasAttribute( 'hidden' ) ) { close(); }
		} );
		overlay.querySelector( '.vh-modal__search' ).addEventListener( 'input', function ( e ) {
			window.clearTimeout( searchTimer );
			var v = e.target.value;
			searchTimer = window.setTimeout( function () { state.q = v; state.page = 1; load(); }, 300 );
		} );
		overlay.querySelector( '.vh-modal__filter' ).addEventListener( 'change', function ( e ) {
			var val = e.target.value;
			if ( state.group === 'assets' ) { state.metric = val; }
			else if ( state.group === 'findings' ) { state.severity = val; }
			state.page = 1; load();
		} );
		overlay.querySelector( '[data-vh-prev]' ).addEventListener( 'click', function () {
			if ( state.page > 1 ) { state.page--; load(); }
		} );
		overlay.querySelector( '[data-vh-next]' ).addEventListener( 'click', function () {
			if ( state.page < state.pages ) { state.page++; load(); }
		} );
	}

	function setFilter() {
		var sel = overlay.querySelector( '.vh-modal__filter' );
		var opts = [];
		if ( state.group === 'assets' ) {
			opts = [ [ 'assets', 'All assets' ], [ 'uncovered', 'Uncovered' ], [ 'archived', 'Archived' ] ];
			sel.value = state.metric;
		} else if ( state.group === 'findings' ) {
			opts = [ [ '', 'All severities' ], [ 'critical', 'Critical' ], [ 'high', 'High' ], [ 'medium', 'Medium' ], [ 'low', 'Low' ] ];
		}
		if ( ! opts.length ) { sel.hidden = true; sel.innerHTML = ''; return; }
		sel.innerHTML = opts.map( function ( o ) {
			var s = ( state.group === 'assets' ? state.metric : state.severity ) === o[0] ? ' selected' : '';
			return '<option value="' + o[0] + '"' + s + '>' + o[1] + '</option>';
		} ).join( '' );
		sel.hidden = false;
	}

	function open( a ) {
		if ( ! overlay ) { build(); }
		var metric = a.getAttribute( 'data-metric' );
		var group = ( metric === 'products' ) ? 'products'
			: ( metric === 'findings' || metric === 'critical' ) ? 'findings' : 'assets';
		state = {
			slug: a.getAttribute( 'data-vendor' ),
			name: a.getAttribute( 'data-vendor-name' ) || '',
			group: group,
			metric: group === 'findings' ? 'findings' : metric,
			severity: metric === 'critical' ? 'critical' : '',
			q: '', page: 1, pages: 1
		};
		overlay.querySelector( '.vh-modal__search' ).value = '';
		overlay.querySelector( '.vh-modal__title' ).textContent = state.name;
		overlay.querySelector( '.vh-modal__sub' ).textContent = '';
		overlay.removeAttribute( 'hidden' );
		document.body.classList.add( 'vh-modal-open' );
		setFilter();
		panel.focus();
		load();
	}

	function close() {
		if ( overlay ) { overlay.setAttribute( 'hidden', '' ); }
		document.body.classList.remove( 'vh-modal-open' );
		state = null;
	}

	function load() {
		var body = overlay.querySelector( '.vh-modal__body' );
		body.setAttribute( 'aria-busy', 'true' );
		body.innerHTML = '<div class="vh-modal__loading">' + esc( ( cfg.i18n && cfg.i18n.loading ) || 'Loading\u2026' ) + '</div>';
		var path = '/vulnhub-dashboard/v1/vendor-drill?vendor=' + encodeURIComponent( state.slug ) +
			'&metric=' + encodeURIComponent( state.metric ) +
			'&severity=' + encodeURIComponent( state.severity ) +
			'&q=' + encodeURIComponent( state.q ) +
			'&page=' + state.page;
		wp.apiFetch( { path: path } ).then( function ( d ) {
			state.pages = d.pages || 1;
			render( d );
		} ).catch( function ( err ) {
			body.innerHTML = '<p class="vh-modal__empty">' + esc( ( err && err.message ) || 'Could not load that list.' ) + '</p>';
		} );
	}

	function render( d ) {
		overlay.querySelector( '.vh-modal__title' ).textContent = d.title;
		overlay.querySelector( '.vh-modal__sub' ).textContent = state.name;
		var exp = overlay.querySelector( '.vh-modal__export' );
		exp.href = ( d.export_url || '' ).replace( /&amp;/g, '&' );

		var body = overlay.querySelector( '.vh-modal__body' );
		if ( ! d.rows || ! d.rows.length ) {
			body.innerHTML = '<p class="vh-modal__empty">' + ( state.q ? 'Nothing matches that search.' : 'Nothing to show.' ) + '</p>';
		} else {
			var thead = '<tr>' + d.columns.map( function ( c ) { return '<th>' + esc( c.label ) + '</th>'; } ).join( '' ) + '</tr>';
			var rows = d.rows.map( function ( r ) {
				return '<tr>' + d.columns.map( function ( c ) {
					var v = r[ c.key ];
					if ( c.key === 'severity' ) {
						return '<td><span class="vh-pill vh-pill--' + esc( v ) + '">' + esc( v ) + '</span></td>';
					}
					var cell = document.createElement( 'td' );
					cell.textContent = ( v === '' || v == null ) ? '—' : v;
					return cell.outerHTML;
				} ).join( '' ) + '</tr>';
			} ).join( '' );
			body.innerHTML = '<div class="vh-modal__scroll"><table class="vh-table vh-modal__table"><thead>' + thead + '</thead><tbody>' + rows + '</tbody></table></div>';
		}
		body.setAttribute( 'aria-busy', 'false' );

		var fmt = function ( n ) { return Number( n ).toLocaleString(); };
		overlay.querySelector( '.vh-modal__count' ).textContent = fmt( d.total ) + ( d.total === 1 ? ' row' : ' rows' );
		overlay.querySelector( '.vh-modal__page' ).textContent = 'Page ' + d.page + ' of ' + d.pages;
		overlay.querySelector( '[data-vh-prev]' ).disabled = d.page <= 1;
		overlay.querySelector( '[data-vh-next]' ).disabled = d.page >= d.pages;
	}

	document.addEventListener( 'click', function ( e ) {
		var a = e.target.closest ? e.target.closest( 'a[data-vh-drill]' ) : null;
		if ( ! a ) { return; }
		e.preventDefault();
		e.stopImmediatePropagation(); // keep vh-motion's link-transition from navigating to the CSV
		open( a );
	} );
}() );

/**
 * Infinite scroll for the findings and assets tables: a sentinel <tr
 * hidden> row at the end of tbody, observed via IntersectionObserver.
 * Fetches the next page from the matching REST fragment endpoint
 * (findings-more / assets-more) using the CURRENT page's own filters
 * (read straight from window.location.search -- exactly the params
 * $_GET already carries in a real page load, forwarded unchanged so the
 * server-side filter parsing can never disagree with what is on screen),
 * and appends the returned row HTML right before the sentinel.
 *
 * Progressive enhancement: the first page is always server-rendered, and
 * the classic Prev/Next pager stays in the DOM as a no-JS/no-REST
 * fallback -- it is only hidden once a first successful fetch proves the
 * REST path actually works here.
 */
( function () {
	'use strict';

	var ENDPOINTS = { findings: 'findings-more', assets: 'assets-more' };

	function hidePagerFallback( sentinel ) {
		var wrap = sentinel.closest( '.vh-tablewrap' ) || sentinel.parentElement;
		var container = wrap ? wrap.parentElement : null;
		if ( ! container ) { return; }
		var pager = container.querySelector( '.vh-pager' );
		if ( pager ) { pager.setAttribute( 'hidden', '' ); }
	}

	function attach( sentinel ) {
		var kind = sentinel.getAttribute( 'data-vh-infinite' );
		if ( ! ENDPOINTS[ kind ] ) { return; }

		var loading = false;
		var done    = false;

		function loadMore() {
			if ( loading || done ) { return; }

			var offset = parseInt( sentinel.getAttribute( 'data-offset' ), 10 ) || 0;
			var total  = parseInt( sentinel.getAttribute( 'data-total' ), 10 ) || 0;

			if ( offset >= total ) { done = true; observer.disconnect(); return; }

			/*
			 * Never toggle `hidden` here. The sentinel used to be rendered
			 * hidden and unhidden at this point -- but `[hidden]` is
			 * display:none, a display:none element has no box, and an element
			 * with no box never intersects, so this function was the only
			 * thing that could reveal the sentinel and the observer was the
			 * only thing that could call this function. Neither ever ran. The
			 * pager underneath quietly carried the table instead, which is why
			 * nothing looked broken.
			 */
			loading = true;
			sentinel.classList.add( 'is-loading' );

			var params = new URLSearchParams( window.location.search );
			params.delete( 'vp' );
			params.delete( 'ap' );
			params.delete( 'page_id' );
			params.set( 'offset', String( offset ) );
			var relPath = '/vulnhub-dashboard/v1/' + ENDPOINTS[ kind ] + '?' + params.toString();

			wp.apiFetch( { path: relPath } ).then( function ( d ) {
				if ( d.html ) {
					sentinel.insertAdjacentHTML( 'beforebegin', d.html );
					hidePagerFallback( sentinel );
				}
				sentinel.setAttribute( 'data-offset', String( d.offset ) );
				sentinel.setAttribute( 'data-total', String( d.total ) );
				sentinel.classList.remove( 'is-loading' );
				loading = false;
				if ( d.offset >= d.total || ! d.count ) {
					done = true;
					observer.disconnect();
				}
			} ).catch( function () {
				// Leave the classic pager visible/functional; just stop
				// trying to auto-load further pages.
				sentinel.classList.remove( 'is-loading' );
				loading = false;
				done = true;
				observer.disconnect();
			} );
		}

		var observer = new IntersectionObserver( function ( entries ) {
			entries.forEach( function ( entry ) {
				if ( entry.isIntersecting ) { loadMore(); }
			} );
		}, { rootMargin: '400px 0px' } );

		observer.observe( sentinel );
	}

	function init() {
		document.querySelectorAll( '[data-vh-infinite]' ).forEach( attach );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );

/*
 * Select-all on the hand-to-your-administrator block.
 *
 * Bound here rather than as an onclick attribute: the connector help is run
 * through wp_kses_post, which strips event handlers, so an inline handler
 * silently never arrives.
 */
( function () {
	document.addEventListener( 'focusin', function ( e ) {
		var el = e.target;
		if ( el && el.classList && el.classList.contains( 'vh-aws-ask' ) ) {
			el.select();
		}
	} );
}() );

/*
 * AWS account form: show only the credential fields the chosen mode uses.
 *
 * Both fieldsets are rendered server-side so the form still works without
 * JavaScript -- this only hides the half that does not apply.
 */
( function () {
	function sync( select ) {
		var form = select.closest( 'form' );
		if ( ! form ) { return; }
		var mode = select.value;
		form.querySelectorAll( '.vh-aws-mode' ).forEach( function ( fs ) {
			fs.hidden = ! fs.classList.contains( 'vh-aws-mode--' + mode );
		} );
	}

	function init() {
		document.querySelectorAll( '[data-vh-aws-mode]' ).forEach( function ( sel ) {
			sync( sel );
			sel.addEventListener( 'change', function () { sync( sel ); } );
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );

/*
 * Generic dialog opener, and a client-side table filter.
 *
 * The opener hijacks a real link (?add=1) rather than replacing it, so the
 * button still works with JavaScript off -- the server renders the dialog
 * already open when that parameter is present.
 */
( function () {
	function openers() {
		/*
		 * Delegated on document with a capture-phase listener, not bound to
		 * each element.
		 *
		 * vh-motion.js listens for anchor clicks on document and navigates
		 * programmatically to run its page transition. preventDefault() alone
		 * does not stop that -- it is not following the default action, it is
		 * calling location itself -- so the opener has to win the event before
		 * vh-motion sees it at all. Capture phase plus stopPropagation does
		 * that; the same collision is already worked around for the CSV
		 * drill-down links further up this file.
		 *
		 * The anchor keeps its real href (?add=1) so the button still works
		 * with JavaScript off, where the server renders the dialog open.
		 */
		document.addEventListener( 'click', function ( e ) {
			var el = e.target.closest ? e.target.closest( '[data-vh-dialog]' ) : null;
			if ( ! el ) { return; }

			var dlg = document.getElementById( el.getAttribute( 'data-vh-dialog' ) );
			if ( ! dlg || typeof dlg.showModal !== 'function' ) { return; }

			e.preventDefault();
			e.stopPropagation();
			if ( ! dlg.open ) { dlg.showModal(); }
		}, true );

		// A server-rendered <dialog open> is non-modal; promote it so the
		// backdrop and Escape behave the same however it was opened.
		document.querySelectorAll( 'dialog[open]' ).forEach( function ( dlg ) {
			if ( typeof dlg.showModal === 'function' ) {
				dlg.close();
				dlg.showModal();
			}
		} );
	}

	function filters() {
		document.querySelectorAll( '[data-vh-filter]' ).forEach( function ( input ) {
			var table = document.getElementById( input.getAttribute( 'data-vh-filter' ) );
			if ( ! table ) { return; }

			var count = document.querySelector( '[data-vh-filter-count]' );
			var empty = document.querySelector( '[data-vh-filter-empty]' );
			var total = count ? count.textContent.trim() : '';

			input.addEventListener( 'input', function () {
				var q = input.value.trim().toLowerCase();
				var shown = 0;

				table.querySelectorAll( 'tbody tr[data-vh-row]' ).forEach( function ( tr ) {
					var hit = ! q || tr.getAttribute( 'data-vh-row' ).indexOf( q ) !== -1;
					tr.hidden = ! hit;
					if ( hit ) { shown++; }
				} );

				if ( count ) { count.textContent = q ? shown + ' of ' + total : total; }
				if ( empty ) { empty.hidden = shown !== 0; }
			} );
		} );
	}

	function init() { openers(); filters(); }

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );

/* ============================================================
   Portal admin redesign — progressive enhancement.
   Nav filter, Settings sub-tabs, help popovers, scope chips,
   dirty tracking and the unsaved-changes save bar. All optional:
   with JS off the nav is a plain list, all panels and help are
   visible, and the save bar is always shown.
   ============================================================ */
( function () {
	'use strict';

	// Signals to the stylesheet that enhancements are live (hides bubbles and
	// inactive tab panels until opened; hides the always-on save bar).
	document.documentElement.classList.add( 'vh-js' );

	function ready( fn ) {
		if ( 'loading' === document.readyState ) { document.addEventListener( 'DOMContentLoaded', fn ); }
		else { fn(); }
	}

	ready( function () {
		adminNavFilter();
		settings();
		ownerPrivacy();
	} );

	/* ---- Owner column: mask personal names by default, eye toggle reveals ---- */
	function ownerPrivacy() {
		var KEY = 'vh-owners-shown';
		var shown = false;
		try { shown = '1' === localStorage.getItem( KEY ); } catch ( e ) {}

		function apply() {
			[].slice.call( document.querySelectorAll( '[data-vh-owner-toggle]' ) ).forEach( function ( b ) {
				var t = b.closest( 'table' );
				if ( t ) { t.classList.toggle( 'vh-owners-shown', shown ); }
				b.setAttribute( 'aria-pressed', shown ? 'true' : 'false' );
				var lbl = shown ? 'Hide owner names' : 'Show owner names';
				b.setAttribute( 'title', lbl );
				b.setAttribute( 'aria-label', lbl );
			} );
		}

		document.addEventListener( 'click', function ( e ) {
			if ( ! e.target.closest( '[data-vh-owner-toggle]' ) ) { return; }
			shown = ! shown;
			try { localStorage.setItem( KEY, shown ? '1' : '0' ); } catch ( err ) {}
			apply();
		} );

		apply();
	}

	/* ---- Admin section nav: client-side filter ---- */
	function adminNavFilter() {
		var nav = document.querySelector( '[data-vh-adm-nav]' );
		if ( ! nav ) { return; }
		var input = nav.querySelector( '[data-vh-adm-filter]' );
		var nomatch = nav.querySelector( '[data-vh-adm-nomatch]' );
		if ( ! input ) { return; }
		var items = [].slice.call( nav.querySelectorAll( '[data-vh-adm-item]' ) );

		input.addEventListener( 'input', function () {
			var q = input.value.trim().toLowerCase();
			var any = false;
			items.forEach( function ( a ) {
				var label = ( a.querySelector( '.vh-adm__label' ) || a ).textContent.toLowerCase();
				var hit = '' === q || label.indexOf( q ) !== -1;
				var li = a.closest( 'li' );
				if ( li ) { li.hidden = ! hit; }
				if ( hit ) { any = true; }
			} );
			nav.querySelectorAll( '.vh-adm__group' ).forEach( function ( h ) {
				var ul = h.nextElementSibling;
				var shown = ul ? ul.querySelectorAll( 'li:not([hidden])' ).length : 0;
				h.hidden = 0 === shown;
				if ( ul ) { ul.hidden = 0 === shown; }
			} );
			if ( nomatch ) { nomatch.hidden = any; }
		} );
	}

	/* ---- Settings screen ---- */
	function settings() {
		var form = document.querySelector( '[data-vh-settings]' );
		if ( ! form ) { return; }
		settingsTabs( form );
		settingsHelp( form );
		settingsScopes( form );
		settingsDirty( form );
	}

	function settingsTabs( form ) {
		var strip = form.querySelector( '[data-vh-tabs]' );
		if ( ! strip ) { return; }
		var tabButtons = [].slice.call( strip.querySelectorAll( '[data-vh-tab]' ) );
		var panels = [].slice.call( form.querySelectorAll( '[data-vh-tabpanel]' ) );

		function show( key ) {
			tabButtons.forEach( function ( b ) {
				var on = b.getAttribute( 'data-vh-tab' ) === key;
				b.classList.toggle( 'is-active', on );
				b.setAttribute( 'aria-selected', on ? 'true' : 'false' );
			} );
			panels.forEach( function ( p ) {
				p.classList.toggle( 'is-active', p.getAttribute( 'data-vh-tabpanel' ) === key );
			} );
		}
		tabButtons.forEach( function ( b ) {
			b.addEventListener( 'click', function () { show( b.getAttribute( 'data-vh-tab' ) ); } );
		} );
	}

	function settingsHelp( form ) {
		var toggles = [].slice.call( form.querySelectorAll( '.vh-help' ) );

		/*
		 * The side guide (integration configure screen). On a wide screen a
		 * "?" shows its setting's guidance in the rail's Guide card instead
		 * of a bubble under the field, so the form stays still while reading.
		 * Narrow screens -- where the rail sits below the form, out of sight
		 * -- keep the inline bubble.
		 */
		var panel = form.hasAttribute( 'data-vh-guide-form' ) ? document.querySelector( '[data-vh-guide-panel]' ) : null;
		var panelHead = panel ? panel.querySelector( '[data-vh-guide-heading]' ) : null;
		var panelBody = panel ? panel.querySelector( '[data-vh-guide-body]' ) : null;
		var wide = window.matchMedia ? window.matchMedia( '(min-width: 1100px)' ) : null;

		function sideMode() { return !! ( panel && panelBody && wide && wide.matches ); }

		function clearGuided() {
			toggles.forEach( function ( t ) { t.classList.remove( 'is-guiding' ); } );
			form.querySelectorAll( '.vh-field.is-guided' ).forEach( function ( f ) { f.classList.remove( 'is-guided' ); } );
		}

		function guide( t ) {
			var bubble = document.getElementById( t.getAttribute( 'aria-controls' ) );
			var body = bubble ? bubble.querySelector( '.vh-bubble__body' ) : null;
			var field = t.closest( '.vh-field' );

			clearGuided();
			t.classList.add( 'is-guiding' );
			if ( field ) { field.classList.add( 'is-guided' ); }
			if ( panelHead ) { panelHead.textContent = t.getAttribute( 'data-vh-guide-title' ) || panelHead.textContent; }
			panelBody.innerHTML = body ? body.innerHTML : '';
			panel.classList.remove( 'is-fresh' );
			void panel.offsetWidth; // restart the highlight animation
			panel.classList.add( 'is-fresh' );

			// A rail pushed below the fold by a tall Connection card: bring the
			// guide into view rather than update something nobody can see.
			var r = panel.getBoundingClientRect();
			if ( r.top > window.innerHeight - 80 || r.bottom < 0 ) {
				panel.scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
			}
		}

		function closeAll( except ) {
			toggles.forEach( function ( t ) { if ( t !== except ) { t.setAttribute( 'aria-expanded', 'false' ); } } );
		}
		toggles.forEach( function ( t ) {
			t.addEventListener( 'click', function () {
				if ( sideMode() ) {
					closeAll( null );
					guide( t );
					return;
				}
				var open = 'true' === t.getAttribute( 'aria-expanded' );
				closeAll( t );
				t.setAttribute( 'aria-expanded', open ? 'false' : 'true' );
			} );
		} );
		document.addEventListener( 'keydown', function ( e ) {
			if ( 'Escape' === e.key ) { closeAll( null ); }
		} );
		document.addEventListener( 'click', function ( e ) {
			if ( ! e.target.closest( '.vh-help' ) && ! e.target.closest( '.vh-bubble' ) ) { closeAll( null ); }
		} );
	}

	function settingsScopes( form ) {
		[].slice.call( form.querySelectorAll( '[data-vh-scope-grid]' ) ).forEach( function ( grid ) {
			var key = grid.getAttribute( 'data-vh-scope-grid' );
			var sum = form.querySelector( '[data-vh-scope-sum="' + key + '"]' );
			var chips = [].slice.call( grid.querySelectorAll( '.vh-scope' ) );

			function recompute() {
				var on = 0, assets = 0;
				chips.forEach( function ( c ) {
					var box = c.querySelector( 'input' );
					var isOn = box && box.checked;
					c.classList.toggle( 'is-on', !! isOn );
					if ( isOn ) { on++; assets += parseInt( c.getAttribute( 'data-n' ) || '0', 10 ); }
				} );
				if ( sum ) {
					var total = sum.getAttribute( 'data-total' ) || String( chips.length );
					var mode = sum.getAttribute( 'data-vh-scope-mode' );
					sum.textContent = on + ' OF ' + total + ' STATUSES · ' + assets.toLocaleString() + ' ASSETS ' + ( 'report' === mode ? 'COUNTED' : 'IN SCOPE' );
				}
			}
			grid.addEventListener( 'change', recompute );
			recompute();
		} );
	}

	function settingsDirty( form ) {
		var fields = [].slice.call( form.querySelectorAll( '.vh-field' ) );
		var bar = form.querySelector( '[data-vh-savebar]' );
		var barN = form.querySelector( '[data-vh-savebar-n]' );
		var barNames = form.querySelector( '[data-vh-savebar-names]' );
		var discard = form.querySelector( '[data-vh-discard]' );
		var guard = false;

		function controls( field ) { return [].slice.call( field.querySelectorAll( 'input, select, textarea' ) ); }
		function snap( c ) { return 'checkbox' === c.type ? ( c.checked ? '1' : '0' ) : c.value; }

		fields.forEach( function ( f ) {
			controls( f ).forEach( function ( c ) { c.setAttribute( 'data-vh-snap', snap( c ) ); } );
		} );

		function evaluate() {
			var changed = [];
			fields.forEach( function ( f ) {
				var isDirty = controls( f ).some( function ( c ) { return c.getAttribute( 'data-vh-snap' ) !== snap( c ); } );
				f.classList.toggle( 'is-dirty', isDirty );
				if ( isDirty ) { changed.push( f.getAttribute( 'data-vh-field' ) || '' ); }
			} );
			form.querySelectorAll( '[data-vh-tabpanel]' ).forEach( function ( panel ) {
				var tab = form.querySelector( '[data-vh-tab="' + panel.getAttribute( 'data-vh-tabpanel' ) + '"]' );
				if ( tab ) { tab.classList.toggle( 'is-dirty', !! panel.querySelector( '.is-dirty' ) ); }
			} );
			// The nav row to badge: Settings by default, or whichever section
			// the form names (the integration configure screen says so).
			var navItem = document.querySelector( '[data-vh-adm-item="' + ( form.getAttribute( 'data-vh-nav' ) || 'settings' ) + '"]' );
			if ( navItem ) {
				var pill = navItem.querySelector( '.vh-adm__count' );
				if ( changed.length && ! pill ) {
					pill = document.createElement( 'span' );
					pill.className = 'vh-adm__count';
					navItem.appendChild( pill );
				}
				if ( pill ) {
					if ( changed.length ) { pill.textContent = String( changed.length ); }
					else { pill.remove(); }
				}
			}
			if ( bar ) {
				bar.classList.toggle( 'is-shown', changed.length > 0 );
				if ( barN ) { barN.textContent = 1 === changed.length ? '1 unsaved change' : changed.length + ' unsaved changes'; }
				if ( barNames ) { barNames.textContent = changed.join( ' · ' ); }
			}
			guard = changed.length > 0;
		}

		form.addEventListener( 'input', evaluate );
		form.addEventListener( 'change', evaluate );

		if ( discard ) {
			discard.addEventListener( 'click', function () {
				fields.forEach( function ( f ) {
					controls( f ).forEach( function ( c ) {
						var s = c.getAttribute( 'data-vh-snap' );
						if ( 'checkbox' === c.type ) { c.checked = '1' === s; }
						else { c.value = s; }
					} );
				} );
				form.querySelectorAll( '[data-vh-scope-grid]' ).forEach( function ( g ) {
					g.dispatchEvent( new Event( 'change', { bubbles: true } ) );
				} );
				evaluate();
			} );
		}

		form.addEventListener( 'submit', function () { guard = false; } );
		window.addEventListener( 'beforeunload', function ( e ) {
			if ( guard ) { e.preventDefault(); e.returnValue = ''; return ''; }
		} );

		evaluate();
	}
}() );

/*
 * "Vulnerability on assets" tab: each vulnerability is a <details> row that
 * loads the assets it affects the first time it is opened.
 *
 * Fetched from /vuln-assets with THIS page's own filters (read straight from
 * window.location.search, exactly as infinite scroll does) so the asset list
 * under a vuln can never show a machine the filters above it excluded. The
 * `toggle` event does not bubble, so the listener is attached per row rather
 * than delegated on the document. Progressive enhancement: with no JS/REST
 * the row still opens, showing the "Loading…" line and a working link on it
 * is not needed because the vuln title links to the full detail screen.
 */
( function () {
	'use strict';

	if ( ! window.wp || ! wp.apiFetch ) {
		return;
	}

	function load( details ) {
		var body = details.querySelector( '[data-vh-vuln-assets]' );
		var id   = details.getAttribute( 'data-vh-vuln' );
		if ( ! body || ! id || '1' === body.getAttribute( 'data-vh-loaded' ) ) {
			return;
		}

		body.setAttribute( 'data-vh-loaded', '1' );

		var params = new URLSearchParams( window.location.search );
		params.delete( 'vp' );
		params.delete( 'ap' );
		params.delete( 'page_id' );
		params.set( 'vuln', id );

		wp.apiFetch( { path: '/vulnhub-dashboard/v1/vuln-assets?' + params.toString() } )
			.then( function ( d ) {
				body.innerHTML = d && d.html
					? d.html
					: '<p class="vh-sub vh-muted">' + '—' + '</p>';
			} )
			.catch( function () {
				// Let the reader try again by reopening the row.
				body.setAttribute( 'data-vh-loaded', '0' );
			} );
	}

	function init() {
		document.querySelectorAll( 'details.vh-vulnrow' ).forEach( function ( details ) {
			details.addEventListener( 'toggle', function () {
				if ( details.open ) {
					load( details );
				}
			} );
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );

/*
 * "By product" tab: each product row expands to the outdated assets one
 * update would fix, loaded on first open with the list's own filters.
 */
( function () {
	'use strict';

	if ( ! window.wp || ! wp.apiFetch ) {
		return;
	}

	function load( details ) {
		var body = details.querySelector( '[data-vh-product-assets]' );
		var slug = details.getAttribute( 'data-vh-product' );
		if ( ! body || ! slug || '1' === body.getAttribute( 'data-vh-loaded' ) ) {
			return;
		}

		body.setAttribute( 'data-vh-loaded', '1' );

		var params = new URLSearchParams( window.location.search );
		params.delete( 'vp' );
		params.delete( 'ap' );
		params.delete( 'page_id' );
		params.set( 'product', slug );

		wp.apiFetch( { path: '/vulnhub-dashboard/v1/product-assets?' + params.toString() } )
			.then( function ( d ) {
				body.innerHTML = ( d && d.html ) ? d.html : '<p class="vh-sub vh-muted">—</p>';
			} )
			.catch( function () {
				body.setAttribute( 'data-vh-loaded', '0' );
			} );
	}

	function init() {
		document.querySelectorAll( 'details.vh-prodrow__exp' ).forEach( function ( details ) {
			details.addEventListener( 'toggle', function () {
				if ( details.open ) {
					load( details );
				}
			} );
		} );
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );

/*
 * Live product search on /products/. The whole list is rendered server-side
 * (and works with no JS at all); this filters the already-present rows as you
 * type, with no round-trip. It composes with the platform chips, which reload
 * the page server-side -- search runs within whatever scope is loaded. Matching
 * is on data-vh-name (product name + kind + bundled libraries), so typing a
 * library like 'libcurl' surfaces every app that ships it.
 */
( function () {
	'use strict';

	var cfg = window.VulnHubApp || { i18n: {} };
	var box = document.querySelector( '[data-vh-prodsearch]' );
	if ( ! box ) {
		return;
	}
	var list  = document.querySelector( '.vh-prodlist--full' );
	var input = box.querySelector( '.vh-prodsearch__input' );
	if ( ! list || ! input ) {
		return;
	}

	var rows  = Array.prototype.slice.call( list.querySelectorAll( '.vh-prodrow' ) );
	var count = box.querySelector( '.vh-prodsearch__count' );
	var empty = document.querySelector( '[data-vh-prodsearch-empty]' );
	var total = rows.length;
	var fmt   = ( cfg.i18n && cfg.i18n.searchShowing ) || '%1$s of %2$s';

	box.hidden = false; // reveal the control now that JS can drive it

	function nf( n ) {
		try { return n.toLocaleString(); } catch ( e ) { return '' + n; }
	}

	function apply() {
		var q     = input.value.trim().toLowerCase();
		var terms = q ? q.split( /\s+/ ) : [];
		var shown = 0;

		for ( var i = 0; i < rows.length; i++ ) {
			var hay = rows[ i ].getAttribute( 'data-vh-name' ) || '';
			var ok  = true;
			for ( var t = 0; t < terms.length; t++ ) {
				if ( hay.indexOf( terms[ t ] ) === -1 ) { ok = false; break; }
			}
			rows[ i ].hidden = ! ok;
			if ( ok ) {
				// Force the scroll-reveal state on, or a row filtered in from below
				// the fold (still at opacity 0) would appear blank.
				rows[ i ].classList.add( 'vh-inview' );
				shown++;
			}
		}

		if ( count ) {
			count.textContent = q ? fmt.replace( '%1$s', nf( shown ) ).replace( '%2$s', nf( total ) ) : '';
		}
		if ( empty ) {
			empty.hidden = ! ( q && 0 === shown );
		}
	}

	var raf = null;
	input.addEventListener( 'input', function () {
		if ( raf ) { window.cancelAnimationFrame( raf ); }
		raf = window.requestAnimationFrame( apply );
	} );
	input.addEventListener( 'keydown', function ( e ) {
		if ( 'Escape' === e.key && input.value ) { input.value = ''; apply(); }
	} );
}() );

/* =====================================================================
 * Verify tickets
 *
 * Verify (one ticket) and Verify all tickets start a check job
 * (POST /vulnhub/v1/tickets/check) and poll it until it is done. The job reads
 * each ticket's status, assignee and latest comment from Jira and re-checks
 * its findings; whether it also launches a Tenable scan is a setting, and the
 * server decides -- asking for one does not get one. A check that does scan
 * waits for it, so it can take minutes. The job id is kept for this tab, so
 * leaving and coming back picks the progress up again.
 *
 * "Verify all tickets" asks first, and asks in the page: a browser confirm()
 * cannot say what this site will actually do, cannot be read afterwards, and
 * has nowhere to put the per-ticket result that follows.
 * ===================================================================== */
( function () {
	'use strict';

	var panel = document.querySelector( '[data-vh-check-panel]' );

	if ( ! panel || ! window.wp || ! wp.apiFetch ) {
		return;
	}

	var KEY   = 'vh-ticket-check-job';
	var msg   = panel.querySelector( '[data-vh-check-msg]' );
	var list  = panel.querySelector( '[data-vh-check-list]' );
	var close = panel.querySelector( '[data-vh-check-close]' );
	var timer = null;

	function remember( job ) {
		try {
			if ( job ) { window.sessionStorage.setItem( KEY, job ); } else { window.sessionStorage.removeItem( KEY ); }
		} catch ( e ) {}
	}

	function recalled() {
		try { return window.sessionStorage.getItem( KEY ) || ''; } catch ( e ) { return ''; }
	}

	function buttons( disabled ) {
		document.querySelectorAll( '[data-vh-check], [data-vh-check-all]' ).forEach( function ( b ) {
			b.disabled = disabled;
		} );
	}

	function rows( into, d ) {
		into.textContent = '';

		Object.keys( d.tickets || {} ).forEach( function ( id ) {
			var t  = d.tickets[ id ];
			var li = document.createElement( 'li' );
			var k  = document.createElement( 'strong' );
			k.className = 'vh-mono';
			k.textContent = t.key || ( '#' + id );
			li.appendChild( k );
			li.appendChild( document.createTextNode( ' ' + ( t.message || '' ) ) );
			li.className = 'is-' + ( t.result || t.state || '' );
			into.appendChild( li );
		} );
	}

	/*
	 * How far along, in the two stages a ticket actually goes through: read
	 * from Jira, then re-checked against Tenable. Counting only the second
	 * leaves the bar at 0% for the whole first stage -- which, with a step per
	 * cron tick, is minutes of looking broken while it is working.
	 */
	function counted( d ) {
		var all = Object.keys( d.tickets || {} );
		var read = 0;
		var done = 0;

		all.forEach( function ( id ) {
			var s = d.tickets[ id ].state;
			if ( 'refreshed' === s || 'checked' === s ) { read++; }
			if ( 'checked' === s ) { done++; }
		} );

		return {
			total: all.length,
			read: read,
			done: done,
			pct: all.length ? Math.round( ( ( read + done ) / ( all.length * 2 ) ) * 100 ) : 0
		};
	}

	function show( d ) {
		panel.hidden = false;
		msg.textContent = d.message || '';
		rows( list, d );

		close.hidden = ! d.done;
		buttons( ! d.done );

		if ( dlg && dlg.open ) { showInDialog( d ); }
	}

	function poll( job ) {
		window.clearTimeout( timer );

		wp.apiFetch( { path: '/vulnhub/v1/tickets/check/' + encodeURIComponent( job ) } ).then( function ( d ) {
			show( d );
			if ( d.done ) {
				remember( '' );
				close.textContent = 'Close and refresh';
				return;
			}
			// A rescan takes minutes; nothing changes faster than the cron loop.
			timer = window.setTimeout( function () { poll( job ); }, d.scan && d.scan.launched_at ? 30000 : 5000 );
		} ).catch( function ( e ) {
			remember( '' );
			show( { message: ( e && e.message ) || 'The check could not be read.', done: true } );
		} );
	}

	var dlg     = document.getElementById( 'vh-verify-all' );
	var dLede   = dlg && dlg.querySelector( '[data-vh-verify-lede]' );
	var dList   = dlg && dlg.querySelector( '[data-vh-verify-list]' );
	var dProg   = dlg && dlg.querySelector( '[data-vh-verify-progress]' );
	var dFill   = dlg && dlg.querySelector( '[data-vh-verify-fill]' );
	var dCount  = dlg && dlg.querySelector( '[data-vh-verify-count]' );
	var dStatus = dlg && dlg.querySelector( '[data-vh-verify-status]' );
	var dGo     = dlg && dlg.querySelector( '[data-vh-verify-go]' );
	var dCancel = dlg && dlg.querySelector( '[data-vh-verify-cancel]' );
	// The question as the server wrote it, kept so a second run reads as a
	// question again rather than as the last run's closing message.
	var question = dLede ? dLede.textContent : '';

	function showInDialog( d ) {
		if ( ! dlg ) { return; }

		var n = counted( d );

		dProg.hidden = ! n.total;
		if ( n.total ) {
			dFill.style.width = n.pct + '%';
			// Both stages, named: "0 of 6" against a moving bar reads as stuck.
			dCount.textContent = d.done
				? n.done + ' of ' + n.total + ' checked'
				: 'Read from Jira ' + n.read + ' of ' + n.total + ' · re-checked ' + n.done + ' of ' + n.total;
		}

		dStatus.textContent = d.message || '';
		rows( dList, d );

		if ( d.done ) {
			dGo.disabled    = false;
			dGo.textContent = 'Close and refresh';
			dGo.onclick     = function () { window.location.reload(); };
			dCancel.hidden  = true;
		}
	}

	/* The dialog dressed for a run in progress, whoever started it. */
	function running() {
		dLede.textContent   = 'This runs in the background, a step at a time. You can close this and come back — the progress is picked up again.';
		dCancel.hidden      = true;
		dGo.disabled        = true;
		dGo.textContent     = 'Verifying…';
		dStatus.textContent = 'Reading the check…';
		dProg.hidden        = false;

		if ( ! dlg.open ) { dlg.showModal(); }
	}

	function ask() {
		// Back to the question every time: the dialog is reused, and the last
		// run's results must not read as this one's.
		dLede.textContent   = question;
		dList.textContent   = '';
		dProg.hidden        = true;
		dStatus.textContent = '';
		dCancel.hidden      = false;
		dGo.disabled        = false;
		dGo.textContent     = 'Verify all tickets';

		dGo.onclick = function () {
			dGo.disabled        = true;
			dGo.textContent     = 'Verifying…';
			dCancel.hidden      = true;
			dStatus.textContent = 'Starting the check…';
			// A step runs per cron tick, so this is minutes, not seconds. The
			// job id is kept for the tab: closing this does not stop it.
			running();
			start( { all: true, rescan: true }, 'Starting the check…' );
		};

		if ( ! dlg.open ) { dlg.showModal(); }
	}

	function start( data, label ) {
		buttons( true );
		show( { message: label, done: false } );

		wp.apiFetch( { path: '/vulnhub/v1/tickets/check', method: 'POST', data: data } ).then( function ( d ) {
			if ( ! d.ok || ! d.job ) {
				show( { message: d.message || 'The check did not start.', done: true } );
				return;
			}
			remember( d.job );
			show( d );
			poll( d.job );
		} ).catch( function ( e ) {
			show( { message: ( e && e.message ) || 'The check did not start.', done: true } );
		} );
	}

	document.addEventListener( 'click', function ( e ) {
		var one = e.target.closest( '[data-vh-check]' );
		var all = e.target.closest( '[data-vh-check-all]' );

		if ( one ) {
			start( { ids: [ parseInt( one.getAttribute( 'data-vh-check' ), 10 ) ], rescan: true }, 'Starting the check…' );
		} else if ( all ) {
			// Without the dialog on the page -- the ticket page has the
			// buttons but not the dialog -- fall back to starting directly.
			if ( ! dlg ) {
				start( { all: true, rescan: true }, 'Starting the check…' );
				return;
			}

			/*
			 * A run already going: show it rather than asking again. Asking
			 * would offer to start a second job over the same tickets, which
			 * is work nobody asked for and two sets of results racing into the
			 * same rows.
			 */
			if ( recalled() ) {
				running();
				poll( recalled() );
				return;
			}

			ask();
		}
	} );

	close.addEventListener( 'click', function () {
		window.location.reload();
	} );

	if ( dCancel ) {
		dCancel.addEventListener( 'click', function () { dlg.close(); } );
	}

	if ( recalled() ) {
		poll( recalled() );
	}
}() );

/* =====================================================================
 * Report controls that apply on change (the Tickets page's "raised vs not
 * raised" severity and patch choices). A <noscript> button covers no-JS.
 * ===================================================================== */
( function () {
	'use strict';

	document.addEventListener( 'change', function ( e ) {
		var form = e.target.closest && e.target.closest( 'form[data-vh-autosubmit]' );

		if ( form ) {
			form.submit();
		}
	} );
}() );

/* =====================================================================
 * Ticket comments: read the conversation on a ticket, and reply to it,
 * without opening Jira.
 *
 * The same component is rendered twice by the server -- inside the dialog
 * the Tickets list opens, and inline on the ticket page -- so everything
 * here works against a container rather than against the page, and the two
 * cannot drift apart.
 *
 * A reply defaults to an internal note. Going public notifies whoever raised
 * the request and cannot be undone, so it is never where a stray Enter lands.
 * ===================================================================== */
( function () {
	'use strict';

	var cfg = window.VulnHubApp || { i18n: {} };

	function el( tag, cls, text ) {
		var node = document.createElement( tag );
		if ( cls ) { node.className = cls; }
		if ( null != text ) { node.textContent = String( text ); }
		return node;
	}

	function ago( iso ) {
		var then = Date.parse( ( iso || '' ).replace( ' ', 'T' ) + 'Z' );
		if ( isNaN( then ) ) { return ''; }

		var secs = Math.max( 0, Math.round( ( Date.now() - then ) / 1000 ) );
		var steps = [ [ 31536000, 'y' ], [ 2592000, 'mo' ], [ 604800, 'w' ], [ 86400, 'd' ], [ 3600, 'h' ], [ 60, 'm' ] ];

		for ( var i = 0; i < steps.length; i++ ) {
			if ( secs >= steps[ i ][ 0 ] ) {
				return Math.floor( secs / steps[ i ][ 0 ] ) + steps[ i ][ 1 ] + ' ago';
			}
		}
		return 'just now';
	}

	/* One comment. The body is set as text, never as HTML: it is somebody
	   else's input arriving from another system. */
	function commentNode( c ) {
		var item = el( 'li', 'vh-comment' + ( c.public ? '' : ' vh-comment--internal' ) );
		var head = el( 'div', 'vh-comment__head' );

		head.appendChild( el( 'strong', null, c.author || 'Unknown' ) );
		head.appendChild( el( 'span', 'vh-chip vh-chip--xs vh-chip--' + ( c.public ? 'good' : 'neutral' ), c.public ? 'reply' : 'internal' ) );
		head.appendChild( el( 'span', 'vh-meta', ago( c.created ) ) );

		item.appendChild( head );
		item.appendChild( el( 'div', 'vh-comment__body', c.body || '' ) );
		return item;
	}

	function render( box, comments ) {
		var list = box.querySelector( '[data-vh-comments-list]' );
		list.innerHTML = '';

		if ( ! comments || ! comments.length ) {
			list.appendChild( el( 'p', 'vh-meta', 'No comments on this ticket yet.' ) );
			return;
		}

		// Oldest first: a conversation reads downwards, and the reply box is
		// at the bottom. The API hands them back newest first.
		var ul = el( 'ul', 'vh-comments__items' );
		comments.slice().reverse().forEach( function ( c ) { ul.appendChild( commentNode( c ) ); } );
		list.appendChild( ul );
		list.scrollTop = list.scrollHeight;
	}

	function load( box, id ) {
		var list = box.querySelector( '[data-vh-comments-list]' );
		list.innerHTML = '';
		list.appendChild( el( 'p', 'vh-meta', 'Loading the comments…' ) );

		return wp.apiFetch( { path: '/vulnhub/v1/tickets/' + id + '/comments' } )
			.then( function ( result ) {
				if ( ! result.ok ) {
					list.innerHTML = '';
					list.appendChild( el( 'div', 'vh-notice vh-notice--warn', result.message || 'The comments could not be read.' ) );
					return;
				}
				render( box, result.comments );
			} )
			.catch( function ( error ) {
				list.innerHTML = '';
				list.appendChild( el( 'div', 'vh-notice vh-notice--warn', ( error && error.message ) || cfg.i18n.error || 'The comments could not be read.' ) );
			} );
	}

	function wire( box, id ) {
		var post = box.querySelector( '[data-vh-comment-post]' );
		if ( ! post || post.dataset.vhWired ) { return; }
		post.dataset.vhWired = '1';

		var text   = box.querySelector( '[data-vh-comment-body]' );
		var status = box.querySelector( '[data-vh-comment-status]' );
		var hint   = box.querySelector( '[data-vh-comment-hint]' );

		function isPublic() {
			var on = box.querySelector( 'input[type=radio][value=public]' );
			return !! ( on && on.checked );
		}

		box.addEventListener( 'change', function ( e ) {
			if ( e.target.matches( 'input[type=radio]' ) && hint ) {
				hint.textContent = isPublic()
					? 'The person who raised this will be notified and can read it.'
					: 'Only agents see an internal note.';
				box.classList.toggle( 'is-public', isPublic() );
			}
		} );

		post.addEventListener( 'click', function () {
			var body = ( text.value || '' ).trim();

			if ( ! body ) {
				status.textContent = 'Write something first.';
				text.focus();
				return;
			}

			// Say which kind is about to go out, in the button, while it goes.
			post.disabled = true;
			status.textContent = isPublic() ? 'Posting a reply the customer will see…' : 'Posting an internal note…';

			wp.apiFetch( {
				path: '/vulnhub/v1/tickets/' + id + '/comments',
				method: 'POST',
				data: { body: body, public: isPublic() ? 1 : 0 }
			} )
				.then( function ( result ) {
					text.value = '';
					status.textContent = result.message || 'Posted.';
					post.disabled = false;
					return load( box, id );
				} )
				.catch( function ( error ) {
					// The text stays in the box: it was not posted, and
					// retyping it is the last thing anyone wants.
					status.textContent = ( error && error.message ) || cfg.i18n.error || 'The comment was not posted.';
					post.disabled = false;
				} );
		} );
	}

	/* ---- the dialog on the Tickets list ---- */
	document.addEventListener( 'click', function ( event ) {
		var button = event.target.closest ? event.target.closest( '[data-vh-comments]' ) : null;
		if ( ! button ) { return; }
		event.preventDefault();

		var dlg = document.getElementById( 'vh-ticket-comments' );
		if ( ! dlg ) { return; }

		var id  = parseInt( button.dataset.vhComments, 10 );
		var box = dlg.querySelector( '.vh-comments' );
		var row = button.closest( 'tr' );
		var key = button.dataset.vhCommentsKey || '';

		dlg.querySelector( '#vh-comments-title' ).textContent = key || 'Ticket';

		var lede = dlg.querySelector( '[data-vh-comments-lede]' );
		var summary = row ? row.querySelector( 'td:nth-child(3)' ) : null;
		lede.textContent = summary ? summary.textContent.trim() : '';

		// The link out stays available: this panel is a convenience, not a
		// replacement for the ticket in Jira.
		var jira = dlg.querySelector( '[data-vh-comments-jira]' );
		var href = row ? row.querySelector( 'td:first-child a[target=_blank]' ) : null;
		if ( jira ) {
			jira.hidden = ! href;
			if ( href ) { jira.href = href.href; }
		}

		box.setAttribute( 'data-vh-comments-for', String( id ) );
		if ( ! dlg.open ) { dlg.showModal(); }

		wire( box, id );
		load( box, id );
	} );

	document.addEventListener( 'click', function ( event ) {
		var close = event.target.closest ? event.target.closest( '[data-vh-comments-close]' ) : null;
		if ( ! close ) { return; }
		var dlg = close.closest( 'dialog' );
		if ( dlg ) { dlg.close(); }
	} );

	/* ---- the panel on the ticket page ---- */
	document.addEventListener( 'DOMContentLoaded', function () {
		document.querySelectorAll( '.vh-comments--inline[data-vh-comments-for]' ).forEach( function ( box ) {
			var id = parseInt( box.getAttribute( 'data-vh-comments-for' ), 10 );
			if ( ! id ) { return; }
			wire( box, id );
			load( box, id );
		} );
	} );
}() );

/* ---------------------------------------------------------------------
 * Change status: move a ticket through its Jira workflow from here.
 *
 * What a workflow offers depends on the issue's current status and on what
 * the connecting account may do, so the set is read from Jira when the
 * dialog opens, never assumed. Required fields are built from what Jira
 * says that transition's screen demands — a close screen that wants a
 * resolution gets a select of the resolutions Jira itself offers.
 * ------------------------------------------------------------------ */
( function () {
	'use strict';

	var cfg = window.VulnHubApp || { i18n: {} };

	function el( tag, cls, text ) {
		var node = document.createElement( tag );
		if ( cls ) { node.className = cls; }
		if ( null != text ) { node.textContent = String( text ); }
		return node;
	}

	function ago( iso ) {
		var then = Date.parse( ( iso || '' ).replace( ' ', 'T' ) + 'Z' );
		if ( isNaN( then ) ) { return ''; }
		var secs = Math.max( 0, Math.round( ( Date.now() - then ) / 1000 ) );
		var steps = [ [ 86400, 'd' ], [ 3600, 'h' ], [ 60, 'm' ] ];
		for ( var i = 0; i < steps.length; i++ ) {
			if ( secs >= steps[ i ][ 0 ] ) { return Math.floor( secs / steps[ i ][ 0 ] ) + steps[ i ][ 1 ] + ' ago'; }
		}
		return 'just now';
	}

	var state = { id: 0, transitions: [], progress: null };

	/* The fields the chosen transition needs, and the warning it deserves. */
	function onChoice( dlg ) {
		var pick   = dlg.querySelector( '[data-vh-move-to]' );
		var holder = dlg.querySelector( '[data-vh-move-fields]' );
		var warn   = dlg.querySelector( '[data-vh-move-warn]' );
		var go     = dlg.querySelector( '[data-vh-move-go]' );
		var chosen = null;

		state.transitions.forEach( function ( t ) {
			if ( t.id === pick.value ) { chosen = t; }
		} );

		holder.textContent = '';
		warn.hidden = true;
		go.disabled = ! chosen;

		if ( ! chosen ) { return; }

		/* A transition VulnHub cannot fill in correctly is offered, then
		   refused with the reason — hiding it would look like Jira does not
		   allow the move at all, which is a different and wrong message. */
		if ( chosen.unsupported && chosen.unsupported.length ) {
			warn.textContent = 'Moving to ' + chosen.to + ' needs ' + chosen.unsupported.join( ', ' )
				+ ', which VulnHub cannot fill in correctly. Make this move in Jira.';
			warn.hidden = false;
			go.disabled = true;
			return;
		}

		( chosen.fields || [] ).forEach( function ( field ) {
			var row = el( 'label', 'vh-move__row' );
			row.appendChild( el( 'span', null, field.name ) );

			var input;
			if ( 'select' === field.kind ) {
				input = el( 'select' );
				input.appendChild( el( 'option', null, '—' ) );
				input.firstChild.value = '';
				( field.options || [] ).forEach( function ( option ) {
					var node = el( 'option', null, option.label );
					node.value = option.id;
					input.appendChild( node );
				} );
			} else {
				input = el( 'input' );
				input.type = 'text';
			}

			input.setAttribute( 'data-vh-move-field', field.id );
			input.required = true;
			row.appendChild( input );
			holder.appendChild( row );
		} );

		/* Closing while the scanner still sees findings is allowed — it can be
		   a false positive, or work tracked elsewhere — but never silently. */
		var p = state.progress;
		if ( 'done' === chosen.category && p && p.findings > p.findings_fixed ) {
			warn.textContent = 'Tenable still shows ' + ( p.findings - p.findings_fixed ) + ' of '
				+ p.findings + ' findings on this ticket unfixed, as at ' + ago( p.as_of )
				+ '. Closing it anyway is recorded, and the ticket goes to awaiting verification.';
			warn.hidden = false;
		}
	}

	function load( dlg, id ) {
		var lede = dlg.querySelector( '[data-vh-move-lede]' );
		var form = dlg.querySelector( '[data-vh-move-form]' );
		var pick = dlg.querySelector( '[data-vh-move-to]' );

		form.hidden = true;
		lede.textContent = 'Reading what the workflow offers…';

		return wp.apiFetch( { path: '/vulnhub/v1/tickets/' + id + '/transitions' } )
			.then( function ( result ) {
				if ( ! result || ! result.ok ) {
					lede.textContent = ( result && result.message ) || 'The available statuses could not be read.';
					return;
				}

				state.transitions = result.transitions || [];
				state.progress    = result.progress || null;

				if ( ! state.transitions.length ) {
					/* Jira answered, with nothing. That is a real answer — a
					   workflow often has no move out of a closed status — so
					   say which status it is stuck in and offer the way out,
					   rather than leaving an empty dropdown to be read as a
					   loading failure. */
					lede.textContent = result.status
						? 'This ticket is ' + result.status + ', and its Jira workflow offers no move out of that status for your account. Open it in Jira if it has to change.'
						: 'Jira offers no status change on this ticket for your account.';

					var out = dlg.querySelector( '[data-vh-move-jira]' );
					if ( out && result.url ) { out.href = result.url; out.hidden = false; }

					/* Nothing to move to, so there is no Move button. A
					   disabled primary button still reads as the thing to
					   press, and the answer here is Jira, not this dialog. */
					dlg.querySelector( '[data-vh-move-go]' ).hidden = true;
					return;
				}

				lede.textContent = 'This moves the ticket in Jira. VulnHub reads the result straight back.';
				pick.textContent = '';

				state.transitions.forEach( function ( t ) {
					var node = el( 'option', null, t.to + ( t.name && t.name !== t.to ? ' (' + t.name + ')' : '' ) );
					node.value = t.id;
					pick.appendChild( node );
				} );

				form.hidden = false;
				onChoice( dlg );
			} )
			.catch( function ( error ) {
				lede.textContent = ( error && error.message ) || cfg.i18n.error || 'The available statuses could not be read.';
			} );
	}

	function submit( dlg ) {
		var go     = dlg.querySelector( '[data-vh-move-go]' );
		var status = dlg.querySelector( '[data-vh-move-status]' );
		var pick   = dlg.querySelector( '[data-vh-move-to]' );
		var note   = dlg.querySelector( '[data-vh-move-note]' );
		var fields = {};
		var missing = null;

		dlg.querySelectorAll( '[data-vh-move-field]' ).forEach( function ( input ) {
			var value = ( input.value || '' ).trim();
			if ( ! value && ! missing ) { missing = input; }
			fields[ input.getAttribute( 'data-vh-move-field' ) ] = value;
		} );

		if ( missing ) {
			status.textContent = 'Fill in what Jira needs first.';
			missing.focus();
			return;
		}

		go.disabled = true;
		status.textContent = 'Moving the ticket…';

		wp.apiFetch( {
			path: '/vulnhub/v1/tickets/' + state.id + '/transitions',
			method: 'POST',
			data: { transition: pick.value, fields: fields, note: ( note.value || '' ).trim() }
		} )
			.then( function ( result ) {
				status.textContent = ( result && result.message ) || 'Moved.';
				// The status, the verification clock and the findings all just
				// changed server side. Redraw from what was recorded.
				window.location.reload();
			} )
			.catch( function ( error ) {
				status.textContent = ( error && error.message ) || cfg.i18n.error || 'The ticket was not moved.';
				go.disabled = false;
			} );
	}

	document.addEventListener( 'click', function ( event ) {
		if ( ! event.target.closest ) { return; }

		var open = event.target.closest( '[data-vh-move]' );
		if ( open ) {
			event.preventDefault();
			var dlg = document.getElementById( 'vh-ticket-move' );
			if ( ! dlg ) { return; }

			state.id = parseInt( open.dataset.vhMove, 10 );
			dlg.querySelector( '#vh-move-title' ).textContent =
				'Change status' + ( open.dataset.vhMoveKey ? ' — ' + open.dataset.vhMoveKey : '' );
			dlg.querySelector( '[data-vh-move-status]' ).textContent = '';
			var move = dlg.querySelector( '[data-vh-move-go]' );
			move.disabled = true;
			move.hidden   = false;

			var out = dlg.querySelector( '[data-vh-move-jira]' );
			if ( out ) { out.hidden = true; }
			if ( ! dlg.open ) { dlg.showModal(); }
			load( dlg, state.id );
			return;
		}

		var cancel = event.target.closest( '[data-vh-move-cancel]' );
		if ( cancel ) {
			var box = cancel.closest( 'dialog' );
			if ( box ) { box.close(); }
			return;
		}

		var go = event.target.closest( '[data-vh-move-go]' );
		if ( go ) { submit( go.closest( 'dialog' ) ); }
	} );

	document.addEventListener( 'change', function ( event ) {
		if ( event.target.matches && event.target.matches( '[data-vh-move-to]' ) ) {
			onChoice( event.target.closest( 'dialog' ) );
		}
	} );

	/* ---- "Send an updated list to Jira": review, edit the note, then send ---- */
	( function () {
		function mkEl( tag, cls, text ) {
			var n = document.createElement( tag );
			if ( cls ) { n.className = cls; }
			if ( null != text ) { n.textContent = String( text ); }
			return n;
		}

		var dlg = null;
		var current = { id: 0, status: null, assets: [] };

		function dialog() {
			if ( dlg ) { return dlg; }
			var d = mkEl( 'dialog', 'vh-review' );
			d.setAttribute( 'aria-labelledby', 'vh-reattach-title' );
			d.innerHTML =
				'<form method="dialog" class="vh-modal__x"><button aria-label="Close">&times;</button></form>' +
				'<h2 id="vh-reattach-title">Send an updated list to Jira</h2>' +
				'<p class="vh-review__lede">Nothing has been sent yet. This is exactly what will go to Jira when you press Send.</p>' +
				'<div class="vh-review__body" data-vh-ra-body></div>' +
				'<label class="vh-ra-note-label" for="vh-ra-note">Comment posted on the ticket (edit or add your own)</label>' +
				'<textarea id="vh-ra-note" class="vh-ra-note" rows="4" data-vh-ra-note></textarea>' +
				'<div class="vh-review__foot">' +
					'<span class="vh-review__status" data-vh-ra-status role="status"></span>' +
					'<button type="button" class="vh-btn vh-btn--ghost" data-vh-ra-cancel>Cancel</button>' +
					'<button type="button" class="vh-btn vh-btn--primary" data-vh-ra-send disabled>Send to Jira</button>' +
				'</div>';
			document.body.appendChild( d );
			d.querySelector( '[data-vh-ra-cancel]' ).addEventListener( 'click', function () { d.close(); } );
			d.querySelector( '[data-vh-ra-send]' ).addEventListener( 'click', send );
			dlg = d;
			return d;
		}

		function renderPreview( p ) {
			var d = dialog();
			var body = d.querySelector( '[data-vh-ra-body]' );
			body.innerHTML = '';

			var meta = mkEl( 'p', 'vh-ra-meta' );
			meta.appendChild( mkEl( 'strong', null, p.scope || '' ) );
			meta.appendChild( document.createTextNode( ' · ' + ( p.filename || '' ) + ' · ' + ( p.rows || 0 ) + ' rows' ) );
			body.appendChild( meta );

			if ( p.sample && p.sample.length ) {
				var table = mkEl( 'table', 'vh-ra-table' );
				var thead = mkEl( 'thead' ), htr = mkEl( 'tr' );
				( p.columns || [] ).forEach( function ( c ) { htr.appendChild( mkEl( 'th', null, c ) ); } );
				thead.appendChild( htr ); table.appendChild( thead );
				var tbody = mkEl( 'tbody' );
				p.sample.forEach( function ( row ) {
					var tr = mkEl( 'tr' );
					( p.columns || [] ).forEach( function ( c ) { tr.appendChild( mkEl( 'td', null, row[ c ] != null ? row[ c ] : '' ) ); } );
					tbody.appendChild( tr );
				} );
				table.appendChild( tbody );
				body.appendChild( table );
				if ( p.more > 0 ) { body.appendChild( mkEl( 'p', 'vh-sub vh-muted', '…and ' + p.more + ' more in the attached file.' ) ); }
			}

			d.querySelector( '[data-vh-ra-note]' ).value = p.default_note || '';
			d.querySelector( '[data-vh-ra-send]' ).disabled = false;
			d.querySelector( '[data-vh-ra-status]' ).textContent = '';
			if ( ! d.open ) { d.showModal(); }
		}

		function send() {
			var d = dialog();
			var note = d.querySelector( '[data-vh-ra-note]' ).value;
			var sendBtn = d.querySelector( '[data-vh-ra-send]' );
			var statusEl = d.querySelector( '[data-vh-ra-status]' );
			sendBtn.disabled = true;
			statusEl.textContent = 'Attaching and posting…';
			wp.apiFetch( { path: '/vulnhub/v1/tickets/' + current.id + '/attachment', method: 'POST', data: { note: note, asset_ids: current.assets } } )
				.then( function ( result ) {
					d.close();
					if ( current.status ) { current.status.textContent = ( result && result.message ) || 'Attached.'; }
				} )
				.catch( function ( error ) {
					sendBtn.disabled = false;
					statusEl.textContent = ( error && error.message ) || 'The list was not attached.';
				} );
		}

		document.addEventListener( 'click', function ( event ) {
			var button = event.target.closest ? event.target.closest( '[data-vh-reattach]' ) : null;
			if ( ! button ) { return; }
			event.preventDefault();

			// A selection button carries its assets; the ticket-wide one has none.
			current.assets = [];
			if ( button.hasAttribute( 'data-vh-reattach-assets' ) ) {
				try { current.assets = JSON.parse( button.dataset.vhReattachAssets || '[]' ) || []; } catch ( e ) { current.assets = []; }
				if ( ! current.assets.length ) { return; }
			}
			current.id     = parseInt( button.dataset.vhReattach, 10 );
			current.status = button.parentNode.querySelector( '[data-vh-reattach-status]' );

			var d = dialog();
			var body = d.querySelector( '[data-vh-ra-body]' );
			body.innerHTML = '';
			body.appendChild( mkEl( 'p', 'vh-sub vh-muted', 'Building the current list…' ) );
			d.querySelector( '[data-vh-ra-note]' ).value = '';
			d.querySelector( '[data-vh-ra-send]' ).disabled = true;
			d.querySelector( '[data-vh-ra-status]' ).textContent = '';
			if ( ! d.open ) { d.showModal(); }

			wp.apiFetch( { path: '/vulnhub/v1/tickets/' + current.id + '/attachment', method: 'POST', data: { preview: true, asset_ids: current.assets } } )
				.then( function ( result ) { renderPreview( result || {} ); } )
				.catch( function ( error ) {
					var b = d.querySelector( '[data-vh-ra-body]' );
					b.innerHTML = '';
					b.appendChild( mkEl( 'p', 'vh-ra-err', ( error && error.message ) || 'The list could not be built.' ) );
				} );
		} );
	}() );
}() );

/*
 * Ticket page, findings grouped by asset: pick assets (this page, or every
 * asset the filter matches), then send an updated list for just those or set
 * them aside on this ticket. The selection survives paging within the tab.
 */
( function () {
	var bar = document.querySelector( '[data-vh-tf-sel]' );
	if ( ! bar || ! window.wp || ! window.wp.apiFetch ) { return; }

	var ticket = parseInt( bar.dataset.ticket, 10 );
	var key    = 'vh-tf-pick-' + ticket;
	var all    = [];
	var picked = {};
	try { all = JSON.parse( bar.dataset.all || '[]' ) || []; } catch ( e ) { all = []; }
	try { ( JSON.parse( window.sessionStorage.getItem( key ) || '[]' ) || [] ).forEach( function ( id ) { picked[ id ] = true; } ); } catch ( e ) {}

	var countEl = bar.querySelector( '[data-vh-tf-count]' );
	var sendBtn = bar.querySelector( '[data-vh-reattach]' );
	var status  = bar.querySelector( '[data-vh-aside-status]' );

	function ids() { return Object.keys( picked ).map( function ( k ) { return parseInt( k, 10 ); } ); }
	function boxes() { return Array.prototype.slice.call( document.querySelectorAll( '[data-vh-tf-pick]' ) ); }

	function sync() {
		var list = ids();
		boxes().forEach( function ( b ) { b.checked = !! picked[ b.value ]; } );
		var page = document.querySelector( '[data-vh-tf-page]' );
		if ( page ) { var bs = boxes(); page.checked = bs.length > 0 && bs.every( function ( b ) { return b.checked; } ); }
		countEl.textContent = list.length ? list.length + ( 1 === list.length ? ' asset selected' : ' assets selected' ) : 'None selected';
		Array.prototype.forEach.call( bar.querySelectorAll( '[data-vh-needs-sel]' ), function ( b ) { b.disabled = 0 === list.length; } );
		if ( sendBtn ) { sendBtn.setAttribute( 'data-vh-reattach-assets', JSON.stringify( list ) ); }
		try { window.sessionStorage.setItem( key, JSON.stringify( list ) ); } catch ( e ) {}
	}

	document.addEventListener( 'change', function ( event ) {
		var t = event.target;
		if ( ! t || ! t.matches ) { return; }
		if ( t.matches( '[data-vh-tf-pick]' ) ) {
			if ( t.checked ) { picked[ t.value ] = true; } else { delete picked[ t.value ]; }
			sync();
		} else if ( t.matches( '[data-vh-tf-page]' ) ) {
			boxes().forEach( function ( b ) { if ( t.checked ) { picked[ b.value ] = true; } else { delete picked[ b.value ]; } } );
			sync();
		}
	} );

	bar.querySelector( '[data-vh-tf-all]' ).addEventListener( 'click', function () {
		all.forEach( function ( id ) { picked[ id ] = true; } );
		sync();
	} );
	bar.querySelector( '[data-vh-tf-none]' ).addEventListener( 'click', function () {
		picked = {};
		sync();
	} );

	function aside( reason ) {
		var list = ids();
		if ( ! list.length ) { return; }
		var sel   = bar.querySelector( '[data-vh-aside-reason]' );
		var label = sel.options[ sel.selectedIndex ] ? sel.options[ sel.selectedIndex ].text : reason;
		var n     = list.length + ( 1 === list.length ? ' asset' : ' assets' );
		var ask   = reason
			? 'Set ' + n + ' aside on this ticket as "' + label + '"?\n\nTheir open findings stop counting as outstanding on this ticket only, and leave its updated list. Nothing is sent to Jira. You can take them back.'
			: 'Take ' + n + ' back into this ticket? Their open findings count as outstanding again.';
		if ( ! window.confirm( ask ) ) { return; }
		status.textContent = 'Saving…';
		window.wp.apiFetch( {
			path: '/vulnhub/v1/tickets/' + ticket + '/aside',
			method: 'POST',
			data: { asset_ids: list, reason: reason, note: reason ? bar.querySelector( '[data-vh-aside-note]' ).value : '' }
		} ).then( function ( r ) {
			status.textContent = ( r && r.message ) || 'Saved.';
			picked = {};
			sync();
			window.location.reload();
		} ).catch( function ( err ) {
			status.textContent = ( err && err.message ) || 'Not saved.';
		} );
	}

	bar.querySelector( '[data-vh-aside-set]' ).addEventListener( 'click', function () { aside( bar.querySelector( '[data-vh-aside-reason]' ).value ); } );
	bar.querySelector( '[data-vh-aside-clear]' ).addEventListener( 'click', function () { aside( '' ); } );

	sync();
}() );
