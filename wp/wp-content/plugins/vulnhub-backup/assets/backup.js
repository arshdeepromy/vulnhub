/**
 * Backup & Restore screen behaviour: job progress polling and the chunked
 * restore uploader. Mirrors vulnhub-import's uploader shape (begin/chunk/
 * finish against a REST namespace), pointed at vulnhub-backup/v1 instead.
 */
( function () {
	'use strict';

	if ( typeof VulnHubBackup === 'undefined' ) {
		return;
	}

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

	/* Poll any running job rows on the page every few seconds. */
	function pollJobs() {
		var rows = document.querySelectorAll( '#vh-backup-jobs tr[data-job-id]' );
		rows.forEach( function ( row ) {
			var id = row.getAttribute( 'data-job-id' );
			restFetch( 'jobs/' + id ).then( function ( job ) {
				if ( ! job || ! job.status ) {
					return;
				}
				var cells = row.querySelectorAll( 'td' );
				if ( cells.length >= 4 ) {
					cells[ 2 ].textContent = job.phase;
					cells[ 3 ].textContent = job.statusLabel;
				}
				if ( job.status === 'running' ) {
					restFetch( 'jobs/' + id + '/pass', { method: 'POST' } );
				}
			} );
		} );
	}

	if ( document.getElementById( 'vh-backup-jobs' ) ) {
		setInterval( pollJobs, 5000 );
	}

	/* Chunked restore upload. */
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
			restFetch( 'restore/start', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify( { key: uploadedKey, confirmDomain: typed } ),
			} )
				.then( function ( result ) {
					setStatus( 'Restore started (job #' + result.jobId + '). This can take a while — reloading the page will show progress.' );
				} )
				.catch( function ( e ) {
					setStatus( e.message );
				} );
		} );
	}
} )();

