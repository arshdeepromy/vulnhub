/**
 * Classification rules screen.
 *
 * Progressive enhancement only: every action works without this file — the
 * arrows reorder, the conditions already rendered submit, and the noscript
 * "Save order" button exists. This adds drag reordering and the condition
 * repeater on top.
 */
( function () {
	'use strict';

	var config = { valueless: [ 'empty', 'exists' ] };
	var configEl = document.getElementById( 'vh-rules-config' );

	if ( configEl ) {
		try {
			config = JSON.parse( configEl.textContent ) || config;
		} catch ( e ) {
			/* keep the defaults */
		}
	}

	/* ------------------------------------------------------- conditions. */

	var list = document.getElementById( 'vh-rules-conditions' );
	var template = document.getElementById( 'vh-rules-condition-template' );
	var addButton = document.getElementById( 'vh-rules-add-condition' );

	/**
	 * Show the tag category box only for tag fields, and hide the value box
	 * for operators that do not take one.
	 */
	function syncRow( row ) {
		var field = row.querySelector( '.vh-rules__cfield' );
		var op = row.querySelector( '.vh-rules__cop' );
		var key = row.querySelector( '.vh-rules__ckey' );
		var value = row.querySelector( '.vh-rules__cvalue' );

		if ( key && field ) {
			key.hidden = 'tag' !== field.value;
		}
		if ( value && op ) {
			value.hidden = -1 !== config.valueless.indexOf( op.value );
		}
	}

	function syncAll() {
		if ( ! list ) {
			return;
		}
		Array.prototype.forEach.call(
			list.querySelectorAll( '.vh-rules__condition' ),
			syncRow
		);
	}

	function nextIndex() {
		var rows = list ? list.querySelectorAll( '.vh-rules__condition' ) : [];
		var highest = -1;

		Array.prototype.forEach.call( rows, function ( row ) {
			var index = parseInt( row.getAttribute( 'data-index' ), 10 );
			if ( ! isNaN( index ) && index > highest ) {
				highest = index;
			}
		} );

		return highest + 1;
	}

	if ( list && template && addButton ) {
		addButton.addEventListener( 'click', function () {
			var index = nextIndex();
			var markup = template.innerHTML.replace( /__i__/g, String( index ) );
			var holder = document.createElement( 'div' );

			holder.innerHTML = markup;

			var row = holder.firstElementChild;
			if ( ! row ) {
				return;
			}

			list.appendChild( row );
			syncRow( row );

			var first = row.querySelector( 'select' );
			if ( first ) {
				first.focus();
			}
		} );

		list.addEventListener( 'click', function ( event ) {
			var button = event.target.closest( '.vh-rules__remove' );
			if ( ! button ) {
				return;
			}

			var rows = list.querySelectorAll( '.vh-rules__condition' );
			if ( rows.length < 2 ) {
				return;
			}

			button.closest( '.vh-rules__condition' ).remove();
		} );

		list.addEventListener( 'change', function ( event ) {
			var row = event.target.closest( '.vh-rules__condition' );
			if ( row ) {
				syncRow( row );
			}
		} );

		syncAll();
	}

	/* ----------------------------------------------------- drag ordering. */

	var table = document.getElementById( 'vh-rules-table' );
	var orderForm = document.getElementById( 'vh-rules-order' );
	var orderValue = document.getElementById( 'vh-rules-order-value' );

	if ( ! table || ! orderForm || ! orderValue ) {
		return;
	}

	var body = table.querySelector( 'tbody' );
	var dragged = null;

	if ( ! body ) {
		return;
	}

	body.addEventListener( 'dragstart', function ( event ) {
		var row = event.target.closest( 'tr[data-rule-id]' );
		if ( ! row ) {
			return;
		}

		dragged = row;
		row.classList.add( 'is-dragging' );

		if ( event.dataTransfer ) {
			event.dataTransfer.effectAllowed = 'move';
			event.dataTransfer.setData( 'text/plain', row.getAttribute( 'data-rule-id' ) );
		}
	} );

	body.addEventListener( 'dragover', function ( event ) {
		if ( ! dragged ) {
			return;
		}

		event.preventDefault();

		var over = event.target.closest( 'tr[data-rule-id]' );
		if ( ! over || over === dragged ) {
			return;
		}

		var box = over.getBoundingClientRect();
		var after = ( event.clientY - box.top ) > ( box.height / 2 );

		if ( after ) {
			over.parentNode.insertBefore( dragged, over.nextSibling );
		} else {
			over.parentNode.insertBefore( dragged, over );
		}
	} );

	body.addEventListener( 'drop', function ( event ) {
		event.preventDefault();
	} );

	body.addEventListener( 'dragend', function () {
		if ( ! dragged ) {
			return;
		}

		dragged.classList.remove( 'is-dragging' );
		dragged = null;

		var ids = [];
		Array.prototype.forEach.call(
			body.querySelectorAll( 'tr[data-rule-id]' ),
			function ( row ) {
				ids.push( row.getAttribute( 'data-rule-id' ) );
			}
		);

		orderValue.value = ids.join( ',' );
		orderForm.submit();
	} );
}() );

