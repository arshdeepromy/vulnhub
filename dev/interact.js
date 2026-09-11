/*
 * Functional pass: click the things a user clicks, and assert the page
 * actually did what it says. Rendering clean is not the same as working.
 *
 *   node dev/interact.js
 */
const fs = require('fs');
const { chromium } = require('playwright');

const BASE = 'http://localhost:8093';
let pass = 0, fail = 0;
const errors = [];

function check(name, ok, detail) {
  (ok ? pass++ : fail++);
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  -- ' + detail : ''}`);
}

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 200)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 200)); });

  const pw = fs.readFileSync('/srv/vulnhub/.admin_pass', 'utf8').trim();
  await page.goto(`${BASE}/wp-login.php`, { waitUntil: 'domcontentloaded' });
  await page.fill('#user_login', (process.env.VH_ADMIN_USER || 'admin'));
  await page.fill('#user_pass', pw);
  await Promise.all([page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}), page.click('#wp-submit')]);

  // ---------------------------------------------------------------- nav.
  console.log('\nnavigation');
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  for (const label of ['Vulnerabilities', 'Assets', 'Tickets', 'Exceptions', 'Dashboard']) {
    await page.click(`.vh-nav__link:has-text("${label}")`);
    await page.waitForLoadState('networkidle');
    const active = await page.textContent('.vh-nav__link.is-active').catch(() => '');
    check(`nav to ${label}`, (active || '').trim() === label, `active is "${(active || '').trim()}"`);
  }

  // ------------------------------------------------------------- filters.
  console.log('\nvulnerability filters');
  await page.goto(`${BASE}/vulnerabilities/`, { waitUntil: 'networkidle' });
  const totalOf = async () => {
    const t = await page.textContent('.vh-page-head .vh-sub');
    return parseInt((t.match(/[\d,]+/) || ['0'])[0].replace(/,/g, ''), 10);
  };
  const all = await totalOf();
  // Derived, not a magic number: the fixture changes every time an export is
  // imported, and a hard-coded 354,279 turned a data refresh into a red build.
  const expected = await page.evaluate(async () => {
    const r = await fetch('/wp-json/vulnhub/v1/summary', { credentials: 'same-origin' });
    return r.ok ? (await r.json()).open_total : null;
  });
  check(
    'unfiltered total matches the open finding count',
    expected === null ? all > 0 : all === expected,
    String(all)
  );

  await page.selectOption('select[name="severity"]', 'critical');
  await page.click('.vh-filters button[type="submit"], .vh-filters .vh-btn:has-text("Apply")');
  await page.waitForLoadState('networkidle');
  const crit = await totalOf();
  check('severity=critical narrows the set', crit > 0 && crit < all, `${crit} of ${all}`);
  check('severity survives into the control', await page.inputValue('select[name="severity"]') === 'critical');

  await page.fill('input[name="search"]', 'OpenSSL');
  await page.click('.vh-filters button[type="submit"], .vh-filters .vh-btn:has-text("Apply")');
  await page.waitForLoadState('networkidle');
  const both = await totalOf();
  // Narrowing must never widen. Whether a given term still has a critical hit
  // depends on the data loaded, so zero is a legitimate answer -- what would
  // be a bug is a search that returns more than the filter it refines.
  check('search narrows further', both <= crit, `${both} with search, ${crit} without`);

  const firstTitle = (await page.textContent('tbody tr td:nth-child(3)').catch(() => '')) || '';
  // Only meaningful when the filter left something to look at. With no
  // critical OpenSSL findings loaded, an empty table is the right answer and
  // asserting on a row that does not exist tests the fixture, not the search.
  check(
    'a search hit mentions the term',
    both === 0 ? firstTitle.trim() === '' : /openssl/i.test(firstTitle),
    both === 0 ? 'no rows to check — nothing critical matches' : firstTitle.trim().slice(0, 60)
  );

  await page.click('.vh-filters a:has-text("Reset"), .vh-filters .vh-btn:has-text("Reset")');
  await page.waitForLoadState('networkidle');
  check('reset restores the full set', await totalOf() === all);

  // ---------------------------------------------------------- pagination.
  console.log('\npagination');
  const firstIdOf = async () => (await page.getAttribute('tbody tr input[type="checkbox"]', 'value').catch(() => null));
  const p1 = await firstIdOf();
  const next = await page.$('.vh-pager a:has-text("Next"), .vh-pager a[rel="next"]');
  if (next) {
    await next.click();
    await page.waitForLoadState('networkidle');
    const p2 = await firstIdOf();
    check('page 2 shows different rows', p1 && p2 && p1 !== p2, `${p1} -> ${p2}`);
  } else {
    check('pager present', false, 'no Next link found');
  }

  // ------------------------------------------------------------- sorting.
  console.log('\nsorting');
  await page.goto(`${BASE}/vulnerabilities/?orderby=due_at&order=ASC`, { waitUntil: 'networkidle' });
  const dues = await page.$$eval('tbody tr td:nth-child(6)', (tds) => tds.map((t) => t.textContent.trim()).slice(0, 5));
  check('orderby=due_at returns rows', dues.length > 0, dues.join(' | ').slice(0, 80));

  // -------------------------------------------------------- theme toggle.
  console.log('\ntheme toggle');
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  const before = await page.getAttribute('html', 'data-theme');
  await page.click('[data-vh-theme]');
  await page.waitForTimeout(200);
  const after = await page.getAttribute('html', 'data-theme');
  check('toggle stamps a theme', after && after !== before, `${before} -> ${after}`);
  const stored = await page.evaluate(() => { try { return localStorage.getItem('vh-theme'); } catch (e) { return null; } });
  check('choice is remembered', stored === after, String(stored));
  await page.reload({ waitUntil: 'networkidle' });
  check('choice survives a reload', await page.getAttribute('html', 'data-theme') === after);
  await page.click('[data-vh-theme]');
  await page.waitForTimeout(150);

  // ------------------------------------------------------- account menu.
  console.log('\naccount menu');
  const openBefore = await page.evaluate(() => document.querySelector('details.vh-account').open);
  await page.click('details.vh-account > summary');
  await page.waitForTimeout(150);
  const box = await page.$eval('.vh-account__menu', (el) => {
    const r = el.getBoundingClientRect();
    return { w: r.width, h: r.height, right: r.right, pos: getComputedStyle(el).position };
  });
  check('menu opens', !openBefore && await page.evaluate(() => document.querySelector('details.vh-account').open));
  // What matters is that it overlays rather than joining the layout: opening
  // it must not push the page down. Asserting `position: absolute` tested the
  // portal's own topbar; the chrome is a Theme Builder template now and how it
  // achieves the overlay is Elementor's business, not the test's.
  const pushed = await page.evaluate(() => {
    const main = document.querySelector('main');
    const details = document.querySelector('details.vh-account');
    const top = main.getBoundingClientRect().top;
    details.open = false;
    const closed = main.getBoundingClientRect().top;
    details.open = true;
    return Math.abs(top - closed);
  });
  check('the menu overlays rather than pushing the page down', pushed < 2, pushed + 'px of shift, position: ' + box.pos);
  check('menu stays on screen', box.right <= 1441, `right=${Math.round(box.right)}`);
  check('menu has real size', box.w > 180 && box.h > 60, `${Math.round(box.w)}x${Math.round(box.h)}`);

  // -------------------------------------------------------- table views.
  console.log('\nchart table views');
  await page.goto(`${BASE}/`, { waitUntil: 'networkidle' });
  const views = await page.$$('details.vh-tableview');
  check('charts offer a table view', views.length > 0, `${views.length} found`);
  if (views.length) {
    await views[0].evaluate((d) => { d.open = true; });
    await page.waitForTimeout(150);
    const rows = await views[0].$$eval('tbody tr', (r) => r.length);
    const scrolls = await views[0].$eval('.vh-tableview__scroll', (el) => getComputedStyle(el).overflowX);
    check('table view has rows', rows > 0, `${rows} rows`);
    check('table view scrolls rather than clipping', scrolls === 'auto', scrolls);
  }

  // ------------------------------------------------------------- filters on assets.
  console.log('\nassets');
  await page.goto(`${BASE}/assets/`, { waitUntil: 'networkidle' });
  const assetTotal = await page.textContent('.vh-page-head .vh-sub');
  check('asset count rendered', /[\d,]+/.test(assetTotal), assetTotal.trim().slice(0, 60));
  await page.goto(`${BASE}/assets/?needs_user=1`, { waitUntil: 'networkidle' });
  const gapRows = await page.$$eval('tbody tr', (r) => r.length);
  check('ownership gap filter returns rows', gapRows > 0, `${gapRows} rows`);

  console.log(`\n${pass} passed, ${fail} failed`);
  if (errors.length) {
    console.log('\nconsole/page errors:');
    [...new Set(errors)].slice(0, 10).forEach((e) => console.log('  ' + e));
  } else {
    console.log('no console or page errors throughout');
  }
  await browser.close();
  process.exit(fail ? 1 : 0);
})();
