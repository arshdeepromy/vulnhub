/*
 * Upload a very large CSV through the actual browser UI.
 *
 * The shell harness in vh-import-test drives the same REST endpoints, but it
 * is not the thing operators use. This is: a real file input, the real
 * adaptive slicer, the real progress panel. It stops short of starting the
 * import -- that path is covered by the load test -- and deletes the job it
 * created so a run leaves nothing behind.
 *
 * Run without sudo:
 *   node dev/importpass.js [path-to-csv]
 */
const { chromium } = require('playwright');
const fs = require('fs');

const BASE = 'http://localhost:8093';
const FILE = process.argv[2] || '/home/romy/vh-import-test/tenable-500mb.csv';
const PASS = fs.readFileSync('/home/romy/vulnhub/.portal_test_pass', 'utf8').trim();

let passed = 0;
let failed = 0;

function ok(label, detail) {
  passed++;
  console.log('  ok   ' + label + (detail ? '  -- ' + detail : ''));
}

function bad(label, detail) {
  failed++;
  console.log('  FAIL ' + label + (detail ? '  -- ' + detail : ''));
}

function mb(bytes) {
  return (bytes / 1048576).toFixed(1) + ' MB';
}

(async () => {
  if (!fs.existsSync(FILE)) {
    console.log('no fixture at ' + FILE);
    process.exit(2);
  }

  const size = fs.statSync(FILE).size;
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();

  const problems = [];
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));

  console.log('uploading ' + FILE + ' (' + mb(size) + ')\n');

  await page.goto(BASE + '/sign-in/');
  await page.fill('input[name="log"]', (process.env.VH_PORTAL_USER || 'portal.tester'));
  await page.fill('input[name="pwd"]', PASS);
  await Promise.all([page.waitForNavigation(), page.click('button[type=submit], input[type=submit]')]);

  await page.goto(BASE + '/portal-admin/?section=imports');

  // The screen should promise the real ceiling, not the per-request limit.
  const blurb = (await page.textContent('.vh-panel__head .vh-sub')) || '';

  if (/Files up to/.test(blurb) && !/^This server accepts/.test(blurb.trim())) {
    ok('the screen states the file limit, not the request limit', blurb.trim().slice(0, 70));
  } else {
    bad('the screen states the file limit, not the request limit', blurb.trim().slice(0, 90));
  }

  const began = Date.now();

  await page.setInputFiles('[data-vh-file]', FILE);

  // Progress panel appears while it uploads.
  try {
    await page.waitForSelector('[data-vh-upload]:not([hidden])', { timeout: 20000 });
    ok('the upload panel appears');
  } catch (e) {
    bad('the upload panel appears', e.message);
  }

  // Then the mapping panel, once analysis finishes.
  try {
    await page.waitForSelector('[data-vh-mapping]:not([hidden])', { timeout: 15 * 60 * 1000 });
    const seconds = ((Date.now() - began) / 1000).toFixed(1);
    ok('the file uploaded and was analysed', seconds + 's for ' + mb(size));
  } catch (e) {
    bad('the file uploaded and was analysed', e.message);
    await browser.close();
    process.exit(1);
  }

  const label = (await page.textContent('[data-vh-file-label]')) || '';

  if (label.indexOf('500.0 MB') !== -1 || label.indexOf(mb(size)) !== -1) {
    ok('the whole file arrived', label.trim());
  } else {
    bad('the whole file arrived', label.trim());
  }

  const estimate = (await page.textContent('[data-vh-estimate]')) || '';
  ok('a row estimate was produced', estimate.trim());

  // Clean up. A pending job is cancelled, which is what discards the staged
  // file -- leaving a 500 MB temp file behind after every test run would fill
  // the volume in a fortnight.
  const jobs = await page.evaluate(async () => {
    var cfg = window.VulnHubImport;
    var r = await fetch(cfg.root + 'jobs', {
      credentials: 'same-origin',
      headers: { 'X-WP-Nonce': cfg.restNonce, 'X-VH-Import-Nonce': cfg.nonce },
    });
    return r.json();
  });

  const list = Array.isArray(jobs) ? jobs : jobs.jobs || [];
  const pending = list.filter((j) => j.status === 'pending');

  for (const job of pending) {
    await page.evaluate(async (id) => {
      var cfg = window.VulnHubImport;
      await fetch(cfg.root + 'jobs/' + id + '/cancel', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-WP-Nonce': cfg.restNonce, 'X-VH-Import-Nonce': cfg.nonce },
      });
    }, job.id);
  }

  ok('cleaned up', pending.length + ' pending job(s) cancelled');

  console.log('\n' + passed + ' passed, ' + failed + ' failed');

  if (problems.length) {
    console.log('\nconsole/page errors:');
    Array.from(new Set(problems)).slice(0, 10).forEach((p) => console.log('  ' + p));
  } else {
    console.log('no console or page errors throughout');
  }

  await browser.close();
  process.exit(failed ? 1 : 0);
})();

