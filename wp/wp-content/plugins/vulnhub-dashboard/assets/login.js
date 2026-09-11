/*
 * Sign-in screen behaviour.
 *
 * Three small things: start the asset-sphere canvas, let people reveal what
 * they typed into the password field, and stop the submit button from being
 * pressed twice while the round trip is in flight.
 */
( function () {
	'use strict';

	var scene = document.querySelector( '.vh-login' );

	if ( ! scene ) {
		return;
	}

	/* ------------------------------------------------------------ canvas. */

	var canvas = scene.querySelector( '.vh-login__canvas' );

	if ( canvas && 'function' === typeof window.AttackSurfaceBG ) {
		/*
		 * Reduced motion slows the scene rather than stopping it. A frozen
		 * sphere reads as a broken image; a very slow one reads as calm.
		 */
		var calm = window.matchMedia && window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;

		window.AttackSurfaceBG( canvas, {
			speed: calm ? 0.2 : 1,
			palette: 'cyan',
			threats: ! calm
		} );
	}

	/* ----------------------------------------------------------- password. */

	var toggle = scene.querySelector( '.vh-login__toggle' );
	var field  = scene.querySelector( '#vh-login-pwd' );

	if ( toggle && field ) {
		toggle.addEventListener( 'click', function () {
			var hidden = 'password' === field.type;

			field.type            = hidden ? 'text' : 'password';
			toggle.textContent    = hidden ? 'HIDE' : 'SHOW';
			toggle.setAttribute( 'aria-pressed', hidden ? 'true' : 'false' );
			toggle.setAttribute( 'aria-label', hidden ? 'Hide password' : 'Show password' );

			/*
			 * Focus goes back to the field, at the end of what is already
			 * there -- otherwise revealing the password costs you your place
			 * in it, which is the opposite of helpful.
			 */
			var at = field.value.length;
			field.focus();
			try {
				field.setSelectionRange( at, at );
			} catch ( e ) {}
		} );
	}

	/* ------------------------------------------------------------- submit. */

	var form   = scene.querySelector( '.vh-login__card' );
	var submit = scene.querySelector( '.vh-login__submit' );

	if ( form && submit ) {
		form.addEventListener( 'submit', function () {
			/*
			 * Left enabled deliberately: a disabled submit button is not sent
			 * with the form in some browsers, and the point here is only to
			 * say something is happening, not to police the second press.
			 */
			submit.textContent = submit.getAttribute( 'data-busy' ) || 'Authenticating…';
			submit.setAttribute( 'aria-busy', 'true' );
		} );
	}
}() );
