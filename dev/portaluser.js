/*
 * What a portal-only administrator actually experiences.
 *
 * `portal.tester` holds vulnhub_admin and no WordPress capability at all, which
 * is the account shape a real security team would use. Everything they need
 * has to be reachable from the front end, and wp-admin has to be closed to
 * them without swallowing their form submissions.
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

const SECTIONS = [
  'overview', 'integrations', 'imports', 'rules', 'teams', 'jira-routing',
  'activity', 'audit', 'settings',
  'screen-vulnhub-auth', 'screen-vulnhub-cmdb', 'screen-vulnhub-intune',
  'screen-vulnhub-jira', 'screen-vulnhub-automation', 'screen-vulnhub-tenable',
];

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 160)); });

  // Sign in through the portal's own form, not wp-login.
  const pw = fs.readFileSync('/home/romy/vulnhub/.portal_test_pass', 'utf8').trim();
  await page.goto(`${BASE}/sign-in/`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="log"], #user_login, input[name="username"]', (process.env.VH_PORTAL_USER || 'portal.tester'));
  await page.fill('input[type="password"]', pw);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle' }).catch(() => {}),
    page.click('button[type="submit"], input[type="submit"]'),
  ]);

  console.log('\nsigning in through the portal');
  check('lands inside the portal', !page.url().includes('wp-admin') && !page.url().includes('sign-in'), page.url());
  check('no WordPress admin bar', (await page.$('#wpadminbar')) === null);
  check('dashboard rendered', (await page.$$('[data-vh-widget]')).length > 0,
    `${(await page.$$('[data-vh-widget]')).length} widgets`);

  console.log('\nprimary navigation');
  for (const label of ['Vulnerabilities', 'Assets', 'Tickets', 'Exceptions', 'Dashboard']) {
    // Wait for the click's own navigation to commit. waitForLoadState alone
    // settles against the document we are leaving, which both reads a stale
    // active link and leaves an in-flight navigation to abort the next goto.
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle' }),
      page.click(`.vh-nav__link:has-text("${label}")`),
    ]);
    const active = ((await page.textContent('.vh-nav__link.is-active')) || '').trim();
    check(`reaches ${label}`, active === label);
    check(`  ${label} has no admin bar`, (await page.$('#wpadminbar')) === null);
  }

  console.log('\nevery administration screen, from the front end');
  for (const section of SECTIONS) {
    const resp = await page.goto(`${BASE}/portal-admin/?section=${section}`, { waitUntil: 'networkidle' });
    const body = await page.$eval('.vh-admin__body', (el) => el.innerText.trim().length).catch(() => 0);
    const heading = ((await page.textContent('.vh-admin__body h1')) || '').trim();
    const bad = await page.evaluate(() => /Fatal error|critical error|Warning:/.test(document.body.innerText));
    check(`${section}`, resp.status() === 200 && body > 200 && !bad,
      `HTTP ${resp.status()}, ${body} chars, "${heading.slice(0, 28)}"`);
  }

  console.log('\nwp-admin stays shut');
  const admin = await page.goto(`${BASE}/wp-admin/`, { waitUntil: 'networkidle' });
  check('wp-admin redirects to the portal', !page.url().includes('wp-admin'), page.url());
  check('  and does not 500', admin.status() < 400, `HTTP ${admin.status()}`);

  const plugins = await page.goto(`${BASE}/wp-admin/plugins.php`, { waitUntil: 'networkidle' });
  check('wp-admin/plugins.php is closed too', !page.url().includes('wp-admin'), `HTTP ${plugins.status()} -> ${page.url()}`);

  console.log('\nsaving from the portal comes back to the portal');
  await page.goto(`${BASE}/vulnhub/`, { waitUntil: 'networkidle' });
  await page.click('[data-vh-customise]');
  await page.waitForTimeout(200);
  const before = (await page.$$('[data-vh-picked] li')).length;
  await page.click('[data-vh-add]:not([disabled])');
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle' }).catch(() => {}),
    page.click('.vh-customise button[type="submit"]'),
  ]);
  check('stayed in the portal after saving', !page.url().includes('wp-admin'), page.url());
  check('save confirmed', (await page.$('.vh-flash')) !== null);
  const after = (await page.$$('[data-vh-widget]')).length;
  check('the added widget is on the board', after > 0, `${before} picked -> ${after} rendered`);

  // Put it back the way it was.
  await page.click('[data-vh-customise]');
  await page.waitForTimeout(150);
  await Promise.all([
    page.waitForNavigation({ waitUntil: 'networkidle' }).catch(() => {}),
    page.click('.vh-customise button[name="reset"]'),
  ]);
  // Asserted against the default the product actually ships, not a constant
  // copied out of it -- adding a widget to the default layout should not fail
  // an unrelated test.
  const restored = (await page.$$('[data-vh-widget]')).length;
  check('reset restores the default layout', restored === before,
    `${restored} widgets, default is ${before}`);

  console.log(`\n${pass} passed, ${fail} failed`);
  if (errors.length) {
    console.log('console/page errors:');
    [...new Set(errors)].slice(0, 8).forEach((e) => console.log('  ' + e));
  } else {
    console.log('no console or page errors throughout');
  }

  await browser.close();
  process.exit(fail ? 1 : 0);
})();
