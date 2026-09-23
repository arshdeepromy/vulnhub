/**
 * Backup & Restore screen behaviour: job progress and the chunked restore
 * uploader. Mirrors vulnhub-import's uploader shape (begin/chunk/finish
 * against a REST namespace), pointed at vulnhub-backup/v1 instead.
 *
 * On driving the job from the browser: a pass runs a bounded slice of work
 * (WEB_BUDGET, ~12s) inside the request that asks for it. That is deliberate
 * -- it keeps the heavy lifting out of the cron worker, which holds a flock
 * while it runs and would otherwise stall scheduled syncs for the length of a
 * backup. The cron pass is the fallback for when nobody is watching; a job
 * left to it alone takes about a minute per pass (job 3: 22 minutes wall for
 * 19 seconds of work, against 82 seconds when a browser drove it).
 *
 * What was wrong was not that the browser drives passes, but HOW: a
 * setInterval fired a fresh 12-second pass every 5 seconds for every job row
 * on the page, never waiting for the previous one to come back. Requests
 * piled up, each holding a PHP worker and a database connection, which is
 * what made the whole app feel slow while a backup ran. Now exactly one pass
 * is ever in flight, the next is only scheduled once the last has answered,
 * and polling stops the moment the job reaches a terminal state.
 */
( function () {
	'use strict';

	if ( typeof VulnHubBackup === 'undefined' ) {
		return;
	}

	var POLL_MS = 2000;

	function restFetch( path, options ) {
		options = options || {};
		options.headers = Object.assign(
			{
				'X-WP-Nonce': VulnHubBackup.restNonce,
				'X-VH-Backup-Nonce': VulnHubBackup.nonce,
			},
			options.headers || {}
		);
		return fetch( VulnHubBackup.root + path, options ).then( function ( r ) {
			return r.json().then( function ( body ) {
				if ( ! r.ok ) {
					throw new Error( body.message || VulnHubBackup.i18n.failed );
				}
				return body;
			} );
		} );
	}

	/* ------------------------------------------------------------------
	 * Job progress
	 * ---------------------------------------------------------------- */

	var panel = document.querySelector( '[data-vh-backup-progress]' );

	function el( name ) {
		return panel ? panel.querySelector( '[data-vh-backup-' + name + ']' ) : null;
	}

	function paint( job ) {
		var phase    = el( 'phase' );
		var status   = el( 'status' );
		var fill     = el( 'fill' );
		var track    = el( 'track' );
		var counters = el( 'counters' );
		var error    = el( 'error' );
		var notice   = el( 'notice' );

		if ( phase && job.phaseLabel ) {
			phase.textContent = job.phaseLabel;
		}
		if ( status && job.statusLabel ) {
			status.textContent = job.statusLabel;
		}
		if ( fill && typeof job.progress === 'number' ) {
			fill.style.width = job.progress + '%';
		}
		if ( track && typeof job.progress === 'number' ) {
			track.setAttribute( 'aria-valuenow', String( job.progress ) );
		}
		if ( counters && job.summary ) {
			counters.textContent = job.summary;
		}
		if ( error ) {
			if ( job.error ) {
				error.textContent = job.error;
				error.hidden = false;
			} else {
				error.hidden = true;
			}
		}

		if ( notice ) {
			notice.textContent = job.notice || '';
			notice.hidden = ! job.notice;
		}

		panel.classList.toggle( 'is-running', !! job.running );
		panel.setAttribute( 'data-vh-backup-active', job.running ? '1' : '0' );
	}

	/*
	 * One tick: ask the job where it is, and — only if it is still running —
	 * run one pass. The next tick is scheduled when this one has finished, so
	 * two passes can never overlap however slow the server is.
	 */
	function tick( id ) {
		restFetch( 'jobs/' + id )
			.then( function ( job ) {
				if ( ! job || ! job.status ) {
					return null;
				}

				paint( job );

				if ( ! job.running ) {
					finish( job );
					return null;
				}

				// The pass returns the job as it stands after the slice of
				// work, so this doubles as the next status read.
				return restFetch( 'jobs/' + id + '/pass', { method: 'POST' } ).then( function ( after ) {
					if ( after && after.status ) {
						paint( after );

						if ( ! after.running ) {
							finish( after );
							return null;
						}
					}
					return true;
				} );
			} )
			.then( function ( keepGoing ) {
				if ( keepGoing ) {
					window.setTimeout( function () {
						tick( id );
					}, POLL_MS );
				}
			} )
			.catch( function () {
				// A failed poll is not a failed backup — the job keeps going
				// server-side, and cron will finish it even if this tab has
				// lost the network. Back off rather than hammering.
				window.setTimeout( function () {
					tick( id );
				}, POLL_MS * 5 );
			} );
	}

	/*
	 * The job is over. Reload so every part of the screen — the recent jobs
	 * table, the local backups list with its new set, the button that was
	 * disabled while it ran — is rebuilt from the server rather than half
	 * patched in place here.
	 */
	function finish( job ) {
		var status = el( 'status' );

		if ( status ) {
			if ( job.status === 'done' ) {
				status.textContent = VulnHubBackup.i18n.finished;
			} else if ( job.status === 'failed' ) {
				status.textContent = VulnHubBackup.i18n.failedJob;
			} else if ( job.status === 'cancelled' ) {
				status.textContent = VulnHubBackup.i18n.cancelled;
			}
		}

		window.setTimeout( function () {
			window.location.reload();
		}, 1200 );
	}

	if ( panel && panel.getAttribute( 'data-vh-backup-active' ) === '1' ) {
		tick( panel.getAttribute( 'data-vh-backup-progress' ) );
	}

	/*
	 * Pressing the button posts a normal form and comes back to this screen,
	 * so the only job here is to say something is happening during the round
	 * trip — the first pass runs inside that request and can take a few
	 * seconds.
	 */
	var startForm = document.querySelector( '[data-vh-backup-form]' );

	if ( startForm ) {
		startForm.addEventListener( 'submit', function () {
			var button = startForm.querySelector( 'button[type="submit"]' );

			if ( button ) {
				button.disabled = true;
				button.textContent = VulnHubBackup.i18n.working;
			}
		} );
	}

	/* ------------------------------------------------------------------
	 * Chunked restore upload
	 * ---------------------------------------------------------------- */

	var fileInput   = document.getElementById( 'vh-restore-file' );
	var startButton = document.getElementById( 'vh-restore-start' );
	var confirmBox  = document.getElementById( 'vh-restore-confirm' );
	var progressEl  = document.getElementById( 'vh-restore-progress' );
	var barEl       = document.getElementById( 'vh-restore-bar' );
	var statusEl    = document.getElementById( 'vh-restore-status' );

	var uploadedKey = '';

	if ( ! fileInput ) {
		return;
	}

	function setStatus( text ) {
		if ( statusEl ) {
			statusEl.textContent = text;
		}
	}

	async function uploadFile( file ) {
		progressEl.hidden = false;
		setStatus( VulnHubBackup.i18n.uploading );

		var begun = await restFetch( 'restore/upload/begin', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify( { size: file.size } ),
		} );

		var key    = begun.key;
		var chunk  = begun.chunkSize || VulnHubBackup.chunkSize;
		var offset = 0;

		while ( offset < file.size ) {
			var slice = file.slice( offset, offset + chunk );
			var form  = new FormData();
			form.append( 'key', key );
			form.append( 'offset', String( offset ) );
			form.append( 'chunk', slice );

			var result = await restFetch( 'restore/upload/chunk', { method: 'POST', body: form } );
			offset = result.received;
			barEl.value = Math.round( ( offset / file.size ) * 100 );
			setStatus( VulnHubBackup.i18n.uploading + ' ' + barEl.value + '%' );
		}

		await restFetch( 'restore/upload/finish', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify( { key: key } ),
		} );

		uploadedKey = key;
		setStatus( 'Uploaded. Confirm the domain above and press Restore.' );
		startButton.disabled = false;
	}

	fileInput.addEventListener( 'change', function () {
		if ( fileInput.files[ 0 ] ) {
			uploadFile( fileInput.files[ 0 ] ).catch( function ( e ) {
				setStatus( e.message );
			} );
		}
	} );

	/* ------------------------------------------------------------------
	 * Following a restore
	 *
	 * Not through restFetch(): part way through, the restored users table
	 * replaces the account this tab is signed in as, and every cookie-and-
	 * nonce call from then on answers 401 — sending the stale nonce at all
	 * makes WordPress refuse the request outright. So the watcher sends no
	 * cookie and no nonce, only the one-job token restore/start handed back,
	 * and it drives the passes itself so the restore does not have to wait
	 * for cron's once-a-minute tick.
	 * ---------------------------------------------------------------- */

	var jobBox = document.getElementById( 'vh-restore-job' );

	function part( name ) {
		return jobBox ? jobBox.querySelector( '[data-vh-restore="' + name + '"]' ) : null;
	}

	function paintRestore( job ) {
		if ( ! jobBox || ! job ) {
			return;
		}

		jobBox.hidden = false;
		jobBox.classList.toggle( 'is-running', !! job.running );

		part( 'phase' ).textContent   = job.running ? ( job.phaseLabel || '' ) : ( job.status === 'done' ? VulnHubBackup.i18n.restoreDone : VulnHubBackup.i18n.restoreFailed );
		part( 'status' ).textContent  = job.statusLabel || '';
		part( 'fill' ).style.width    = ( job.progress || 0 ) + '%';
		part( 'track' ).setAttribute( 'aria-valuenow', String( job.progress || 0 ) );
		part( 'summary' ).textContent = job.summary || '';
		part( 'elapsed' ).textContent = job.elapsed ? VulnHubBackup.i18n.elapsed.replace( '%s', job.elapsed ) : '';
		part( 'hint' ).hidden         = ! job.running;

		part( 'error' ).textContent = job.error || '';
		part( 'error' ).hidden      = ! job.error;

		part( 'notice' ).textContent = job.notice || '';
		part( 'notice' ).hidden      = ! job.notice;

		part( 'actions' ).hidden = job.running || job.status !== 'done';
	}

	/*
	 * Being signed out part way through is expected here, and the progress
	 * card says so. WordPress's own session check does not know that: its
	 * heartbeat notices the vanished session and throws a login modal over
	 * the page — over the progress, and over the Sign in button at the end.
	 */
	function quietSessionCheck() {
		if ( window.jQuery ) {
			window.jQuery( document ).off( 'heartbeat-tick.wp-auth-check' );
			window.jQuery( window ).off( 'beforeunload.wp-auth-check' );
		}
		var modal = document.getElementById( 'wp-auth-check-wrap' );
		if ( modal ) {
			modal.parentNode.removeChild( modal );
		}
		document.body.classList.remove( 'modal-open' );
	}

	function watchRestore( id, token, misses ) {
		quietSessionCheck();

		fetch( VulnHubBackup.root + 'restore/jobs/' + id + '/watch', {
			method: 'POST',
			credentials: 'omit',
			headers: { 'X-VH-Restore-Token': token },
		} )
			.then( function ( r ) {
				return r.json().then( function ( body ) {
					if ( ! r.ok ) {
						throw new Error( body.message || VulnHubBackup.i18n.failed );
					}
					return body;
				} );
			} )
			.then( function ( job ) {
				paintRestore( job );

				if ( job.running ) {
					window.setTimeout( function () {
						watchRestore( id, token, 0 );
					}, 1000 );
				} else {
					try {
						window.sessionStorage.removeItem( 'vhRestoreWatch' );
					} catch ( e ) {}
				}
			} )
			.catch( function () {
				// The server can be busy between passes (or restarting with
				// the restored plugins); the job carries on regardless. Say
				// so, and keep asking, backing off.
				misses = ( misses || 0 ) + 1;
				if ( misses >= 2 ) {
					part( 'summary' ).textContent = VulnHubBackup.i18n.reconnecting;
				}
				window.setTimeout( function () {
					watchRestore( id, token, misses );
				}, Math.min( 15000, 2000 * misses ) );
			} );
	}

	// A reload mid-restore lands here signed out or signed in as someone
	// else; pick the job back up from this tab's own record of it.
	try {
		var saved = JSON.parse( window.sessionStorage.getItem( 'vhRestoreWatch' ) || 'null' );
		if ( saved && saved.id && saved.token ) {
			watchRestore( saved.id, saved.token, 0 );
		}
	} catch ( e ) {}

	if ( startButton ) {
		startButton.addEventListener( 'click', function () {
			var typed = ( confirmBox.value || '' ).trim();
			if ( typed.toLowerCase() !== ( VulnHubBackup.siteHost || '' ).toLowerCase() ) {
				alert( VulnHubBackup.i18n.wrongDomain );
				return;
			}
			if ( ! confirm( VulnHubBackup.i18n.confirmRestore ) ) {
				return;
			}

			startButton.disabled = true;
			fileInput.disabled   = true;
			confirmBox.disabled  = true;
			setStatus( VulnHubBackup.i18n.starting );

			restFetch( 'restore/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( { key: uploadedKey, confirmDomain: typed } ),
			} )
				.then( function ( result ) {
					progressEl.hidden = true;
					try {
						window.sessionStorage.setItem( 'vhRestoreWatch', JSON.stringify( { id: result.jobId, token: result.watchToken } ) );
					} catch ( e ) {}
					paintRestore( result.job );
					watchRestore( result.jobId, result.watchToken, 0 );
				} )
				.catch( function ( e ) {
					setStatus( e.message );
					startButton.disabled = false;
					fileInput.disabled   = false;
					confirmBox.disabled  = false;
				} );
		} );
	}
} )();
