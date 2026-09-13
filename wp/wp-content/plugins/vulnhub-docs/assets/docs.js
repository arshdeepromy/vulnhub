/**
 * VulnHub Docs — progressive enhancement.
 *
 * Everything here is optional: with JavaScript off, the sidebar is a plain list
 * of links, the article reads top to bottom, and nothing is hidden. This only
 * adds the on-this-page rail, the sidebar filter, and a contents toggle on
 * phones.
 */
(function () {
	'use strict';

	var root = document.querySelector('[data-vh-docs]');
	if (!root) { return; }

	/* ---- On this page: build from the article's own headings. ---- */
	(function buildToc() {
		var article = root.querySelector('.vh-docs__article');
		var tocNav = root.querySelector('[data-vh-docs-toc]');
		if (!article || !tocNav) { return; }

		var headings = article.querySelectorAll('h2, h3');
		if (!headings.length) {
			var rail = root.querySelector('.vh-docs__toc');
			if (rail) { rail.style.display = 'none'; }
			return;
		}

		var slugify = function (text) {
			return text.toLowerCase().replace(/[^\w]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'section';
		};
		var seen = {};
		var links = [];

		headings.forEach(function (h) {
			var id = h.id;
			if (!id) {
				id = slugify(h.textContent);
				while (seen[id]) { id = id + '-x'; }
				h.id = id;
			}
			seen[id] = true;

			var a = document.createElement('a');
			a.href = '#' + id;
			a.textContent = h.textContent;
			a.className = h.tagName === 'H3' ? 'lvl-3' : 'lvl-2';
			tocNav.appendChild(a);
			links.push(a);
		});

		/* Scroll-spy: highlight the heading nearest the top. */
		if ('IntersectionObserver' in window) {
			var visible = {};
			var spy = new IntersectionObserver(function (entries) {
				entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
				var activeId = null;
				for (var i = 0; i < headings.length; i++) {
					if (visible[headings[i].id]) { activeId = headings[i].id; break; }
				}
				links.forEach(function (a) {
					a.classList.toggle('is-active', a.getAttribute('href') === '#' + activeId);
				});
			}, { rootMargin: '-70px 0px -70% 0px' });
			headings.forEach(function (h) { spy.observe(h); });
		}
	})();

	/* ---- Sidebar filter. ---- */
	(function wireSearch() {
		var input = root.querySelector('[data-vh-docs-search]');
		var nomatch = root.querySelector('[data-vh-docs-nomatch]');
		if (!input) { return; }

		var items = [].slice.call(root.querySelectorAll('[data-vh-docs-item]'));

		input.addEventListener('input', function () {
			var q = input.value.trim().toLowerCase();
			var any = false;

			items.forEach(function (a) {
				var hay = (a.getAttribute('data-title') + ' ' + a.getAttribute('data-summary')).toLowerCase();
				var hit = q === '' || hay.indexOf(q) !== -1;
				var li = a.closest('li');
				if (li) { li.hidden = !hit; }
				if (hit) { any = true; }
			});

			/* Hide a group heading + list when all its items are filtered out. */
			root.querySelectorAll('.vh-docs__toclist .vh-docs__group').forEach(function (h) {
				var ul = h.nextElementSibling;
				var shown = ul ? ul.querySelectorAll('li:not([hidden])').length : 0;
				h.hidden = shown === 0;
				if (ul) { ul.hidden = shown === 0; }
			});

			if (nomatch) { nomatch.hidden = any; }
		});
	})();

	/* ---- Mobile contents toggle. ---- */
	(function wireToggle() {
		var sidebar = root.querySelector('.vh-docs__sidebar');
		if (!sidebar) { return; }

		var btn = document.createElement('button');
		btn.type = 'button';
		btn.className = 'vh-docs__menu-toggle';
		btn.textContent = 'Contents';
		btn.setAttribute('aria-expanded', 'false');
		root.insertBefore(btn, root.firstChild);

		var collapse = function () {
			if (window.matchMedia('(max-width: 782px)').matches) {
				sidebar.hidden = true;
				btn.setAttribute('aria-expanded', 'false');
			} else {
				sidebar.hidden = false;
			}
		};

		btn.addEventListener('click', function () {
			var open = sidebar.hidden;
			sidebar.hidden = !open;
			btn.setAttribute('aria-expanded', open ? 'true' : 'false');
		});

		window.addEventListener('resize', collapse);
		collapse();
	})();
})();
