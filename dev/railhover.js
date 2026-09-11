/* Rail hover-expand check: measures the rail collapsed, on hover, after the
   pointer leaves, and while a nav link holds keyboard focus. Also asserts the
   page content does not reflow when the rail expands over it.

     export NODE_PATH=/usr/local/lib/node_modules/@playwright/mcp/node_modules
     export VH_COOKIE="$(docker compose exec -T wpcli wp eval '
       $m = WP_Session_Tokens::get_instance( 1 ); $e = time() + 900;
       echo wp_generate_auth_cookie( 1, $e, "logged_in", $m->create( $e ) );' | tr -d "\r")"
     node dev/railhover.js
*/

const crypto = require('crypto');
const { chromium } = require('playwright');

const BASE = process.env.VH_BASE || 'http://localhost:8093';

// Auth by injecting a logged-in cookie minted with wp_generate_auth_cookie(),
// so the pass needs no stored admin password and creates no test account.
//
// The cookie NAME is derived here rather than taken from wp-cli. COOKIEHASH is
// md5( siteurl ), and wp-config derives WP_SITEURL from the request host -- so
// a browser on localhost:8093 and a wp-cli run (no HTTP_HOST, falls back to the
// siteurl row, which is the public hostname) compute two different hashes, and
// the cookie wp-cli names is one the browser never reads.
const cookieName = () =>
  'wordpress_logged_in_' + crypto.createHash('md5').update(BASE).digest('hex');

const auth = async (ctx) => {
  const value = process.env.VH_COOKIE;
  if (!value) throw new Error('VH_COOKIE must be set -- see the header');
  await ctx.addCookies([{
    name: cookieName(), value,
    domain: new URL(BASE).hostname, path: '/', httpOnly: true,
  }]);
};

(async () => {
  const b = await chromium.launch();
  const c = await b.newContext({ viewport: { width: 1440, height: 900 } });
  const p = await c.newPage();

  await auth(c);
  await p.goto(`${BASE}/`, { waitUntil: 'networkidle' });

  const railBox = () => p.evaluate(() => {
    const r = document.querySelector('.vh-topbar');
    const main = document.querySelector('.vh-main');
    const txt = document.querySelector('.vh-nav__txt');
    return {
      hasRailClass: document.body.classList.contains('vh-chrome-rail'),
      width: r ? Math.round(r.getBoundingClientRect().width) : null,
      mainLeft: main ? Math.round(main.getBoundingClientRect().left) : null,
      labelWidth: txt ? Math.round(txt.getBoundingClientRect().width) : null,
      labelText: txt ? txt.textContent.trim() : null,
    };
  });

  const settle = () => p.waitForTimeout(400);

  // Park the pointer away from the rail FIRST. Playwright starts the mouse at
  // (0,0), which is inside the rail, so measuring before this reads an already
  // expanded rail and every comparison below becomes meaningless.
  const away = () => p.mouse.move(1200, 500);

  await away();
  await settle();
  const collapsed = await railBox();

  await p.hover('.vh-topbar');
  await settle();
  const hovered = await railBox();

  await away();
  await settle();
  const left = await railBox();

  // Keyboard: focus a nav link with the pointer nowhere near, so only
  // :focus-within can be doing the work.
  await p.evaluate(() => document.querySelector('.vh-nav__link').focus());
  await settle();
  const focused = await railBox();

  await p.evaluate(() => document.activeElement.blur());
  await settle();
  const blurred = await railBox();

  let fails = 0;
  const check = (label, ok, detail) => {
    console.log(`  [${ok ? ' ok ' : 'FAIL'}] ${label}${detail ? '  (' + detail + ')' : ''}`);
    if (!ok) fails++;
  };

  console.log('Rail hover-expand:');
  check('body carries .vh-chrome-rail', collapsed.hasRailClass);
  check('collapsed rail is 64px', collapsed.width === 64, `${collapsed.width}px`);
  check('labels hidden when collapsed', collapsed.labelWidth <= 1, `${collapsed.labelWidth}px`);
  check('expands on hover', hovered.width > collapsed.width, `${collapsed.width} -> ${hovered.width}px`);
  check('labels revealed on hover', hovered.labelWidth > 10, `"${hovered.labelText}" ${hovered.labelWidth}px`);
  check('content does NOT reflow', hovered.mainLeft === collapsed.mainLeft, `main.left stayed ${collapsed.mainLeft}px`);
  check('collapses again on mouse leave', left.width === collapsed.width, `${left.width}px`);
  check('expands on keyboard focus too', focused.width > collapsed.width, `${focused.width}px`);
  check('labels revealed on keyboard focus', focused.labelWidth > 10, `${focused.labelWidth}px`);
  check('collapses again on blur', blurred.width === collapsed.width, `${blurred.width}px`);

  // Phone width must keep the old top-bar behaviour, not a 224px flyout.
  await c.close();
  const cp = await b.newContext({ viewport: { width: 390, height: 844 } });
  const pp = await cp.newPage();
  await auth(cp);
  await pp.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  await pp.hover('.vh-topbar').catch(() => {});
  await pp.waitForTimeout(400);
  const phone = await pp.evaluate(() => {
    const r = document.querySelector('.vh-topbar');
    return r ? Math.round(r.getBoundingClientRect().width) : null;
  });
  console.log('\nPhone (390px):');
  check('rail is not a 224px flyout on phone', phone !== 224, `${phone}px wide`);

  await b.close();
  console.log(`\n${fails === 0 ? 'All checks passed.' : fails + ' check(s) FAILED.'}`);
  process.exit(fails === 0 ? 0 : 1);
})();
