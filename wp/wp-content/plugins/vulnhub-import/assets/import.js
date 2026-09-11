/**
 * VulnHub Import — the browser half of a very large CSV import.
 *
 * Three things here matter.
 *
 * The file is never sent in one request: it is sliced with File.slice() and
 * posted a few megabytes at a time, which is what lets a half-gigabyte export
 * through a server whose post_max_size is 128 M. The slice size is not fixed —
 * each one is timed and the next is sized to land in roughly ten seconds, so a
 * fast link sends thirty-odd big slices and a slow one sends many small ones
 * without any single request sitting long enough for a proxy to give up on it.
 *
 * A slice that fails is retried, and before each retry the client asks the
 * server how much it actually has. Losing a connection at 90% of 500 MB should
 * cost one slice, not the afternoon.
 *
 * Watching the job is optional — the poller only makes an already-running
 * import advance sooner, and closing the tab leaves cron to finish it.
 */
( function () {
	'use strict';

	var cfg = window.VulnHubImport || {};
	var root = document.querySelector( '[data-vh-import]' );

	if ( ! root || ! cfg.root ) {
		return;
	}

	var state = {
		job: null,
		polling: false,
		passing: false,
		reuse: null,
		started: 0,
		startRows: 0
	};

	var el = function ( selector ) {
		return root.querySelector( selector );
	};

	var text = function ( node, value ) {
		if ( node ) {
			node.textContent = value;
		}
	};

	var show = function ( node, visible ) {
		if ( node ) {
			node.hidden = ! visible;
		}
	};

	var t = function ( key ) {
		return ( cfg.i18n && cfg.i18n[ key ] ) || key;
	};

	/* ------------------------------------------------------------- fetch. */

	function api( path, options ) {
		options = options || {};

		var headers = options.headers || {};
		headers['X-WP-Nonce'] = cfg.restNonce;
		headers['X-VH-Import-Nonce'] = cfg.nonce;

		if ( options.json ) {
			headers['Content-Type'] = 'application/json';
			options.body = JSON.stringify( options.json );
		}

		return fetch( cfg.root + path, {
			method: options.method || 'GET',
			credentials: 'same-origin',
			headers: headers,
			body: options.body
		} ).then( function ( response ) {
			return response.json().catch( function () {
				return {};
			} ).then( function ( data ) {
				if ( ! response.ok ) {
					var error = new Error( ( data && data.message ) || t( 'failed' ) );
					error.status = response.status;
					// WP_Error's extra data rides in `data`; the chunk route
					// puts the server's true offset there.
					error.data = ( data && data.data ) || {};
					throw error;
				}
				return data;
			} );
		} );
	}

	function fail( message ) {
		var box = el( '[data-vh-error]' );
		text( box, message );
		show( box, !! message );
	}

	function number( value ) {
		return ( value || 0 ).toLocaleString();
	}

	function bytes( value ) {
		var units = [ 'B', 'KB', 'MB', 'GB' ];
		var i = 0;
		value = value || 0;
		while ( value >= 1024 && i < units.length - 1 ) {
			value = value / 1024;
			i++;
		}
		return ( i === 0 ? value : value.toFixed( 1 ) ) + ' ' + units[ i ];
	}

	function duration( seconds ) {
		seconds = Math.max( 0, Math.round( seconds ) );
		var h = Math.floor( seconds / 3600 );
		var m = Math.floor( ( seconds % 3600 ) / 60 );
		var s = seconds % 60;
		if ( h ) {
			return h + 'h ' + m + 'm';
		}
		if ( m ) {
			return m + 'm ' + s + 's';
		}
		return s + 's';
	}

	/* ------------------------------------------------------------ upload. */

	function pickFile( file ) {
		if ( ! file ) {
			return;
		}

		fail( '' );

		if ( ! /\.(csv|tsv|txt)$/i.test( file.name ) ) {
			fail( t( 'badType' ) );
			return;
		}

		if ( cfg.maxBytes && file.size > cfg.maxBytes ) {
			fail( t( 'tooBig' ) );
			return;
		}

		uploadFile( file );
	}

	/* --------------------------------------------------------- uploading. */

	/** Aim for a slice that takes about this long. */
	var TARGET_SECONDS = 10;

	/** Never go below this, however slow the link. */
	var MIN_CHUNK = 262144;

	/** How many times one slice may be retried before giving up. */
	var MAX_TRIES = 4;

	function wait( ms ) {
		return new Promise( function ( resolve ) {
			setTimeout( resolve, ms );
		} );
	}

	/**
	 * Size the next slice from how long the last one took.
	 *
	 * Doubling and halving rather than solving for the exact number: the
	 * measurement is noisy, and a slice that overshoots the target once should
	 * not send the next one to the floor.
	 */
	function nextChunkSize( current, seconds, ceiling ) {
		var size = current;

		if ( seconds < TARGET_SECONDS / 2 ) {
			size = current * 2;
		} else if ( seconds > TARGET_SECONDS * 2 ) {
			size = Math.floor( current / 2 );
		}

		return Math.max( MIN_CHUNK, Math.min( ceiling, size ) );
	}

	function uploadFile( file ) {
		var drop = el( '[data-vh-drop]' );
		var panel = el( '[data-vh-upload]' );
		var bar = el( '[data-vh-upload-bar]' );
		var pct = el( '[data-vh-upload-pct]' );
		var meta = el( '[data-vh-upload-meta]' );

		if ( drop ) {
			drop.classList.add( 'is-busy' );
		}
		show( panel, true );
		text( el( '[data-vh-upload-label]' ), t( 'uploading' ) + ' — ' + file.name );

		api( 'upload/begin', {
			method: 'POST',
			json: { filename: file.name, size: file.size }
		} ).then( function ( session ) {
			var key = session.key;
			var size = session.chunkSize || cfg.chunkSize || 8388608;
			var ceiling = session.maxChunk || size;
			var offset = 0;
			var startedAt = Date.now();

			function progress() {
				var done = Math.min( 100, Math.round( ( offset / file.size ) * 100 ) );

				if ( bar ) {
					bar.style.width = done + '%';
				}
				text( pct, done + '%' );

				var elapsed = ( Date.now() - startedAt ) / 1000;
				var line = bytes( offset ) + ' / ' + bytes( file.size );

				// Only once there is enough of a sample for the number to
				// mean anything -- a rate quoted off one slice is a lie.
				if ( elapsed > 3 && offset > 0 ) {
					var rate = offset / elapsed;
					var left = Math.round( ( file.size - offset ) / rate );
					line += ' · ' + bytes( Math.round( rate ) ) + '/s';

					if ( left > 0 ) {
						line += ' · ' + duration( left ) + ' left';
					}
				}

				text( meta, line );
			}

			/** Ask the server where it actually got to. */
			function resync() {
				return api( 'upload/status?key=' + encodeURIComponent( key ) ).then( function ( status ) {
					offset = status.received;
					progress();
				} );
			}

			function sendSlice( attempt ) {
				var end = Math.min( offset + size, file.size );
				var slice = file.slice( offset, end );
				var form = new FormData();
				var began = Date.now();

				form.append( 'key', key );
				form.append( 'offset', String( offset ) );
				form.append( 'chunk', slice, 'part' );

				return api( 'upload/chunk', { method: 'POST', body: form } ).then( function ( result ) {
					var seconds = ( Date.now() - began ) / 1000;

					offset = result.received;
					size = nextChunkSize( size, seconds, ceiling );
					progress();
				} ).catch( function ( error ) {
					if ( attempt >= MAX_TRIES ) {
						throw error;
					}

					// A slice that timed out is a slice that was too big for
					// this link. Come back smaller as well as later.
					size = Math.max( MIN_CHUNK, Math.floor( size / 2 ) );

					text( meta, t( 'retrying' ) + ' (' + attempt + '/' + MAX_TRIES + ')' );

					var known = error.data && typeof error.data.received === 'number'
						? Promise.resolve( ( offset = error.data.received ) )
						: resync().catch( function () { /* keep the offset we have */ } );

					return known
						.then( function () { return wait( 1000 * attempt ); } )
						.then( function () { return sendSlice( attempt + 1 ); } );
				} );
			}

			function sendNext() {
				if ( offset >= file.size ) {
					text( meta, t( 'analysing' ) );
					return api( 'upload/finish', {
						method: 'POST',
						json: { key: key, filename: file.name }
					} );
				}

				return sendSlice( 1 ).then( sendNext );
			}

			progress();
			return sendNext();
		} ).then( function ( job ) {
			show( panel, false );
			if ( drop ) {
				drop.classList.remove( 'is-busy' );
			}

			if ( state.reuse && state.reuse.map ) {
				var reuse = state.reuse;
				state.reuse = null;
				return api( 'jobs/' + job.id + '/remap', {
					method: 'POST',
					json: { shape: reuse.shape, map: reuse.map }
				} );
			}

			return job;
		} ).then( function ( job ) {
			if ( job ) {
				renderMapping( job );
			}
		} ).catch( function ( error ) {
			show( panel, false );
			if ( drop ) {
				drop.classList.remove( 'is-busy' );
			}
			fail( error.message );
		} );
	}

	/* ----------------------------------------------------------- mapping. */

	function renderMapping( job ) {
		state.job = job;

		show( el( '[data-vh-mapping]' ), true );
		show( el( '[data-vh-preview-panel]' ), true );
		show( el( '[data-vh-progress]' ), false );

		text( el( '[data-vh-file-label]' ), job.filename + ' · ' + job.sizeLabel );
		text( el( '[data-vh-estimate]' ), '≈ ' + number( job.rowsTotal ) );

		var shape = el( '[data-vh-shape]' );
		if ( shape ) {
			shape.innerHTML = '';
			Object.keys( job.shapes || {} ).forEach( function ( key ) {
				var option = document.createElement( 'option' );
				option.value = key;
				option.textContent = job.shapes[ key ];
				option.selected = key === job.shape;
				shape.appendChild( option );
			} );
		}

		var duplicate = el( '[data-vh-duplicate]' );
		if ( job.duplicate && job.duplicate.id ) {
			text( duplicate, t( 'duplicate' ) + ' ' + job.duplicate.filename + ' — ' + job.duplicate.when +
				' (' + number( job.duplicate.rows ) + ' rows). Importing it again is safe: assets and findings are matched, not duplicated.' );
			show( duplicate, true );
		} else {
			show( duplicate, false );
		}

		var body = el( '[data-vh-map-body]' );
		if ( body ) {
			body.innerHTML = '';

			Object.keys( job.fields || {} ).forEach( function ( field ) {
				var row = document.createElement( 'tr' );

				var label = document.createElement( 'td' );
				label.textContent = job.fields[ field ];
				if ( ( job.required || [] ).indexOf( field ) !== -1 ) {
					var star = document.createElement( 'span' );
					star.className = 'vh-import__req';
					star.textContent = '*';
					star.title = 'Required';
					label.appendChild( star );
				}
				row.appendChild( label );

				var cell = document.createElement( 'td' );
				var select = document.createElement( 'select' );
				select.setAttribute( 'data-vh-col', field );

				var none = document.createElement( 'option' );
				none.value = '';
				none.textContent = '— not mapped —';
				select.appendChild( none );

				( job.headers || [] ).forEach( function ( header ) {
					var option = document.createElement( 'option' );
					option.value = header;
					option.textContent = header;
					option.selected = job.map[ field ] === header;
					select.appendChild( option );
				} );

				select.addEventListener( 'change', submitMap );
				cell.appendChild( select );
				row.appendChild( cell );

				var sample = document.createElement( 'td' );
				var span = document.createElement( 'span' );
				span.className = 'vh-import__sample';
				span.textContent = sampleFor( job, field );
				sample.appendChild( span );
				row.appendChild( sample );

				body.appendChild( row );
			} );
		}

		renderPreview( job );
	}

	function sampleFor( job, field ) {
		var header = job.map ? job.map[ field ] : '';

		if ( ! header || ! job.samples ) {
			return '';
		}

		return job.samples[ header ] || '';
	}

	function renderPreview( job ) {
		var head = el( '[data-vh-preview-head]' );
		var body = el( '[data-vh-preview-body]' );
		var preview = job.preview || { columns: [], rows: [] };

		if ( head ) {
			head.innerHTML = '';
			var tr = document.createElement( 'tr' );
			preview.columns.forEach( function ( column ) {
				var th = document.createElement( 'th' );
				th.scope = 'col';
				th.textContent = column;
				tr.appendChild( th );
			} );
			head.appendChild( tr );
		}

		if ( body ) {
			body.innerHTML = '';
			preview.rows.forEach( function ( cells ) {
				var tr = document.createElement( 'tr' );
				cells.forEach( function ( value ) {
					var td = document.createElement( 'td' );
					td.textContent = value;
					tr.appendChild( td );
				} );
				body.appendChild( tr );
			} );
		}
	}

	function collectMap() {
		var map = {};
		root.querySelectorAll( '[data-vh-col]' ).forEach( function ( select ) {
			if ( select.value ) {
				map[ select.getAttribute( 'data-vh-col' ) ] = select.value;
			}
		} );
		return map;
	}

	function submitMap() {
		if ( ! state.job ) {
			return;
		}

		var shape = el( '[data-vh-shape]' );

		api( 'jobs/' + state.job.id + '/remap', {
			method: 'POST',
			json: {
				shape: shape ? shape.value : state.job.shape,
				map: collectMap()
			}
		} ).then( renderMapping ).catch( function ( error ) {
			fail( error.message );
		} );
	}

	function redetect() {
		if ( ! state.job ) {
			return;
		}

		var shape = el( '[data-vh-shape]' );

		api( 'jobs/' + state.job.id + '/remap', {
			method: 'POST',
			json: { shape: shape ? shape.value : state.job.shape, map: {} }
		} ).then( renderMapping ).catch( function ( error ) {
			fail( error.message );
		} );
	}

	/* ---------------------------------------------------------- progress. */

	function renderProgress( job ) {
		state.job = job;

		show( el( '[data-vh-progress]' ), true );
		show( el( '[data-vh-mapping]' ), false );
		show( el( '[data-vh-preview-panel]' ), false );

		text( el( '[data-vh-progress-file]' ), job.filename + ' · ' + job.sizeLabel + ' · ' + job.statusLabel );
		text( el( '[data-vh-progress-label]' ), number( job.rowsDone ) + ' / ≈ ' + number( job.rowsTotal ) + ' rows' );
		text( el( '[data-vh-progress-pct]' ), job.percent + '%' );

		var bar = el( '[data-vh-progress-bar]' );
		if ( bar ) {
			bar.style.width = Math.max( 0, Math.min( 100, job.percent ) ) + '%';
			bar.className = 'vh-meterblock__fill' +
				( job.status === 'done' ? ' vh-meterblock__fill--ok' : '' ) +
				( job.status === 'failed' ? ' vh-meterblock__fill--bad' : '' );
		}

		var rate = 0;
		if ( state.started && job.rowsDone > state.startRows ) {
			rate = ( job.rowsDone - state.startRows ) / Math.max( 1, ( Date.now() - state.started ) / 1000 );
		} else if ( job.seconds > 0 ) {
			rate = job.rowsDone / job.seconds;
		}

		var remaining = Math.max( 0, job.rowsTotal - job.rowsDone );
		var eta = rate > 0 ? duration( remaining / rate ) : '—';

		text( el( '[data-vh-progress-meta]' ),
			bytes( job.byteOffset ) + ' / ' + bytes( job.sizeBytes ) + ' · ' +
			rate.toFixed( 0 ) + ' ' + t( 'perSecond' ) + ' · ' + t( 'eta' ) + ' ' + eta +
			( job.error ? ' · ' + job.error : '' )
		);

		var counters = el( '[data-vh-counters]' );
		if ( counters ) {
			counters.innerHTML = '';
			cards( job ).forEach( function ( card ) {
				var box = document.createElement( 'div' );
				box.className = 'vh-card' + ( card.tone ? ' vh-card--' + card.tone : '' );

				var label = document.createElement( 'span' );
				label.className = 'vh-card__label';
				label.textContent = card.label;

				var value = document.createElement( 'span' );
				value.className = 'vh-card__value';
				value.textContent = card.value;

				box.appendChild( label );
				box.appendChild( value );

				if ( card.meta ) {
					var meta = document.createElement( 'span' );
					meta.className = 'vh-card__meta';
					meta.textContent = card.meta;
					box.appendChild( meta );
				}

				counters.appendChild( box );
			} );
		}

		var failures = job.failures || [];
		show( el( '[data-vh-failures-wrap]' ), failures.length > 0 );

		var tbody = el( '[data-vh-failures]' );
		if ( tbody ) {
			tbody.innerHTML = '';
			failures.forEach( function ( failure ) {
				var tr = document.createElement( 'tr' );
				var row = document.createElement( 'td' );
				row.className = 'vh-mono';
				row.textContent = failure.row;
				var why = document.createElement( 'td' );
				why.textContent = failure.reason;
				tr.appendChild( row );
				tr.appendChild( why );
				tbody.appendChild( tr );
			} );
		}

		var cancel = el( '[data-vh-cancel]' );
		if ( cancel ) {
			cancel.disabled = job.status !== 'running' && job.status !== 'pending';
		}
	}

	function cards( job ) {
		var c = job.counters || {};

		/*
		 * An Intune device export carries no vulnerabilities at all -- what it
		 * answers is "whose machine is this". Showing the finding counters for
		 * it would report nine zeroes and hide the one number that matters.
		 */
		/*
		 * A Tenable asset export enriches an inventory it does not own: it
		 * creates nothing, and most of its rows are Tenable's account and
		 * identity objects rather than machines. What matters is how many
		 * assets it reached and how many it could not place.
		 */
		if ( job.shape === 'tenable_assets' ) {
			return [
				{ label: 'Rows read', value: number( job.rowsDone ) },
				{ label: 'Assets enriched', value: number( c.assets_updated ), tone: 'ok' },
				{ label: 'Not in inventory', value: number( c.assets_unmatched ), tone: c.assets_unmatched ? 'warn' : '' },
				{ label: 'Non-host rows skipped', value: number( c.rows_skipped ) },
				{ label: 'Cloud account set', value: number( c.cloud_enriched ) },
				{ label: 'Patch group set', value: number( c.patch_groups_set ), tone: 'ok' },
				{ label: 'Failed', value: number( c.rows_failed ), tone: c.rows_failed ? 'bad' : '' },
				{ label: 'Passes', value: number( c.passes ), meta: 'peak ' + bytes( c.peak_memory ) }
			];
		}

		/*
		 * A CMDB export is a register of everything the business owns, not
		 * everything that runs: a good third of it is kit in a cupboard.
		 * Saying so beside the created/updated numbers is the difference
		 * between a skip that looks like a failure and one that looks like
		 * the point.
		 */
		if ( job.shape === 'cmdb' ) {
			return [
				{ label: 'Rows read', value: number( job.rowsDone ) },
				{ label: 'Assets created', value: number( c.assets_created ), tone: 'ok' },
				{ label: 'Assets updated', value: number( c.assets_updated ) },
				{ label: 'Not issued, skipped', value: number( c.assets_unissued ) },
				{ label: 'Other skips', value: number( Math.max( 0, ( c.rows_skipped || 0 ) - ( c.assets_unissued || 0 ) ) ) },
				{ label: 'Failed', value: number( c.rows_failed ), tone: c.rows_failed ? 'bad' : '' },
				{ label: 'Passes', value: number( c.passes ), meta: 'peak ' + bytes( c.peak_memory ) }
			];
		}

		if ( job.shape === 'intune_devices' ) {
			return [
				{ label: 'Rows read', value: number( job.rowsDone ) },
				{ label: 'Assets created', value: number( c.assets_created ), tone: 'ok' },
				{ label: 'Assets matched', value: number( c.assets_updated ) },
				{ label: 'Owners set', value: number( c.owners_set ), tone: 'ok' },
				{ label: 'No primary user', value: number( c.no_owner ), tone: c.no_owner ? 'warn' : '' },
				{ label: 'People added', value: number( c.people_created ) },
				{ label: 'People matched', value: number( c.people_seen ) },
				{ label: 'Failed', value: number( c.rows_failed ), tone: c.rows_failed ? 'bad' : '' },
				{ label: 'Passes', value: number( c.passes ), meta: 'peak ' + bytes( c.peak_memory ) }
			];
		}

		return [
			{ label: 'Rows read', value: number( job.rowsDone ) },
			{ label: 'Assets created', value: number( c.assets_created ), tone: 'ok' },
			{ label: 'Assets matched', value: number( c.assets_updated ) },
			{ label: 'Vulns created', value: number( c.vulns_created ) },
			{ label: 'Findings created', value: number( c.findings_created ), tone: 'ok' },
			{ label: 'Findings updated', value: number( c.findings_updated ) },
			{ label: 'Findings reopened', value: number( c.findings_reopened ), tone: c.findings_reopened ? 'warn' : '' },
			{ label: 'Skipped', value: number( c.rows_skipped ) },
			{ label: 'Failed', value: number( c.rows_failed ), tone: c.rows_failed ? 'bad' : '' },
			{ label: 'Passes', value: number( c.passes ), meta: 'peak ' + bytes( c.peak_memory ) }
		];
	}

	/* ------------------------------------------------------------ polling. */

	function watch( id ) {
		state.started = Date.now();
		state.startRows = 0;

		api( 'jobs/' + id ).then( function ( job ) {
			state.startRows = job.rowsDone;
			renderProgress( job );

			if ( ! state.polling ) {
				state.polling = true;
				poll( id );
				drive( id );
			}
		} ).catch( function ( error ) {
			fail( error.message );
		} );
	}

	function poll( id ) {
		api( 'jobs/' + id ).then( function ( job ) {
			renderProgress( job );

			if ( job.status === 'running' || job.status === 'pending' ) {
				window.setTimeout( function () {
					poll( id );
				}, 1500 );
			} else {
				state.polling = false;
			}
		} ).catch( function () {
			state.polling = false;
		} );
	}

	/**
	 * Nudge the job along from the browser. The server takes an atomic row
	 * lock, so this never races the cron pass — it only means an operator who
	 * is watching does not have to wait for the next tick.
	 */
	function drive( id ) {
		if ( state.passing ) {
			return;
		}

		state.passing = true;

		api( 'jobs/' + id + '/pass', { method: 'POST' } ).then( function ( job ) {
			state.passing = false;
			renderProgress( job );

			if ( job.status === 'running' ) {
				window.setTimeout( function () {
					drive( id );
				}, 400 );
			}
		} ).catch( function () {
			state.passing = false;
		} );
	}

	/* -------------------------------------------------------------- wire. */

	var file = el( '[data-vh-file]' );
	var drop = el( '[data-vh-drop]' );

	if ( drop && file ) {
		drop.addEventListener( 'click', function ( event ) {
			if ( event.target.closest( '[data-vh-pick]' ) || event.target === drop || event.target.closest( '.vh-drop__lead' ) ) {
				file.click();
			}
		} );

		drop.addEventListener( 'keydown', function ( event ) {
			if ( event.key === 'Enter' || event.key === ' ' ) {
				event.preventDefault();
				file.click();
			}
		} );

		[ 'dragenter', 'dragover' ].forEach( function ( name ) {
			drop.addEventListener( name, function ( event ) {
				event.preventDefault();
				drop.classList.add( 'is-over' );
			} );
		} );

		[ 'dragleave', 'drop' ].forEach( function ( name ) {
			drop.addEventListener( name, function ( event ) {
				event.preventDefault();
				drop.classList.remove( 'is-over' );
			} );
		} );

		drop.addEventListener( 'drop', function ( event ) {
			if ( event.dataTransfer && event.dataTransfer.files.length ) {
				pickFile( event.dataTransfer.files[ 0 ] );
			}
		} );

		file.addEventListener( 'change', function () {
			if ( file.files.length ) {
				pickFile( file.files[ 0 ] );
			}
			file.value = '';
		} );
	}

	var form = el( '[data-vh-import-form]' );
	if ( form ) {
		form.addEventListener( 'submit', function ( event ) {
			event.preventDefault();
		} );
	}

	var shapeSelect = el( '[data-vh-shape]' );
	if ( shapeSelect ) {
		shapeSelect.addEventListener( 'change', submitMap );
	}

	var redetectBtn = el( '[data-vh-redetect]' );
	if ( redetectBtn ) {
		redetectBtn.addEventListener( 'click', redetect );
	}

	var startBtn = el( '[data-vh-start]' );
	if ( startBtn ) {
		startBtn.addEventListener( 'click', function () {
			if ( ! state.job || ! window.confirm( t( 'confirmRun' ) ) ) {
				return;
			}

			startBtn.disabled = true;

			api( 'jobs/' + state.job.id + '/start', { method: 'POST' } ).then( function ( job ) {
				startBtn.disabled = false;
				watch( job.id );
			} ).catch( function ( error ) {
				startBtn.disabled = false;
				fail( error.message );
			} );
		} );
	}

	var discardBtn = el( '[data-vh-discard]' );
	if ( discardBtn ) {
		discardBtn.addEventListener( 'click', function () {
			if ( ! state.job ) {
				return;
			}

			api( 'jobs/' + state.job.id + '/cancel', { method: 'POST' } ).then( function () {
				window.location.reload();
			} ).catch( function ( error ) {
				fail( error.message );
			} );
		} );
	}

	var cancelBtn = el( '[data-vh-cancel]' );
	if ( cancelBtn ) {
		cancelBtn.addEventListener( 'click', function () {
			if ( ! state.job || ! window.confirm( t( 'confirmStop' ) ) ) {
				return;
			}

			api( 'jobs/' + state.job.id + '/cancel', { method: 'POST' } ).then( renderProgress ).catch( function ( error ) {
				fail( error.message );
			} );
		} );
	}

	root.querySelectorAll( '[data-vh-watch]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			watch( parseInt( button.getAttribute( 'data-vh-watch' ), 10 ) );
		} );
	} );

	root.querySelectorAll( '[data-vh-stop]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			if ( ! window.confirm( t( 'confirmStop' ) ) ) {
				return;
			}

			api( 'jobs/' + button.getAttribute( 'data-vh-stop' ) + '/cancel', { method: 'POST' } ).then( function () {
				window.location.reload();
			} ).catch( function ( error ) {
				fail( error.message );
			} );
		} );
	} );

	root.querySelectorAll( '[data-vh-rerun]' ).forEach( function ( button ) {
		button.addEventListener( 'click', function () {
			var map = {};

			try {
				map = JSON.parse( button.getAttribute( 'data-vh-map' ) || '{}' );
			} catch ( error ) {
				map = {};
			}

			state.reuse = { shape: button.getAttribute( 'data-vh-shape' ), map: map };

			fail( 'Re-running reuses this job’s shape and column mapping. Choose the same file again — the staged copy is deleted when a job finishes.' );

			if ( drop ) {
				drop.scrollIntoView( { behavior: 'smooth', block: 'center' } );
				drop.focus();
			}
		} );
	} );

	/*
	 * A job the page already knows about, picked back up on load.
	 *
	 * A running import is watched, as before. A *pending* one -- uploaded,
	 * analysed, sitting on the mapping table -- used to be dropped on the
	 * floor: the staged file and the job row were both still on the server,
	 * but a refresh, a closed laptop or a stray Cmd-R left no way back to
	 * them, and the only route forward was to send the whole export up
	 * again. On a 333 MB Tenable file that is not a small mistake to make.
	 *
	 * The job is re-fetched with its preview and the mapping table is drawn
	 * exactly as it was left.
	 */
	var active = root.getAttribute( 'data-active' );
	if ( active ) {
		try {
			var job = JSON.parse( active );

			if ( job && job.id && job.status === 'running' ) {
				watch( job.id );
			} else if ( job && job.id && job.status === 'pending' ) {
				api( 'jobs/' + job.id + '?preview=1' ).then( renderMapping ).catch( function () {
					/* The staged copy has gone; the upload panel is the way on. */
				} );
			}
		} catch ( error ) {
			/* Nothing to resume. */
		}
	}
}() );

