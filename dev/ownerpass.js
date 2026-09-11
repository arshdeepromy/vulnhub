/*
 * Searching by owner.
 *
 * The Owner column is two things stacked -- the person an asset is assigned
 * to, and the team behind them -- and on unassigned kit the team is the only
 * thing shown. Anyone reading that column and typing what they see into
 * Search means either, so both match, along with email and UPN for pasting
 * straight out of a ticket.
 *
 * The counts asserted here were taken from hand-written SQL against the live
 * estate, not from the application, so a regression in the query shows up as
 * a wrong number rather than as two wrong things agreeing.
 *
 * No staff address is written into this file: the email case reads one out of
 * the database at run time and never prints it. Addresses here are production
 * PII and a test fixture in the repo is exactly the shared location they must
 * not reach.
 */
const fs = require('fs');
const { execSync } = require('child_process');
const { chromium } = require('playwright');
const BASE = 'http://localhost:8093';
let pass = 0, fail = 0;
const ok = (n, d) => { pass++; console.log(`ok    ${n}${d ? '  — ' + d : ''}`); };
const bad = (n, d) => { fail++; console.log(`FAIL  ${n}${d ? '  — ' + d : ''}`); };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(String(e).slice(0, 140)));
  page.on('console', m => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });

  const pw = fs.readFileSync('/srv/vulnhub/.admin_pass', 'utf8').trim();
  await page.goto(`${BASE}/sign-in/`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="log"], #user_login, input[name="username"]', 'romy');
  await page.fill('input[type="password"]', pw);
  await page.click('button[type="submit"]', { noWaitAfter: true });
  await page.waitForURL(u => !String(u).includes('sign-in'), { timeout: 60000 });

  /*
   * Expected counts come from hand-written SQL at run time, not from
   * constants. The estate is re-imported regularly -- libcurl went from
   * 11,637 findings to 231 between two runs of the sibling suite -- so a
   * literal here would rot into a false failure within days. The SQL is
   * written independently of the repository's own query, which is the point:
   * the test fails when the two disagree.
   */
  const sql = (q) => {
    const out = execSync(`echo ${JSON.stringify(q)} | /srv/vulnhub/q.sh`, { encoding: 'utf8' })
      .trim().split('\n');
    return parseInt(out[out.length - 1].trim(), 10);
  };

  const OPEN = "f.state IN ('open','reopened') AND f.exception_id = 0";
  const EXPECT = {
    findingsMaxNorth: sql(`SELECT COUNT(*) FROM vh_vulnhub_findings f JOIN vh_vulnhub_assets a ON a.id=f.asset_id JOIN vh_vulnhub_people p ON p.id=a.owner_person_id WHERE p.display_name LIKE '%Max North%' AND ${OPEN}`),
    assetsMaxNorth:   sql("SELECT COUNT(*) FROM vh_vulnhub_assets a JOIN vh_vulnhub_people p ON p.id=a.owner_person_id WHERE p.display_name LIKE '%Max North%'"),
    assetsWintel:     sql("SELECT COUNT(*) FROM vh_vulnhub_assets a JOIN vh_vulnhub_teams t ON t.id=a.team_id WHERE t.name LIKE '%Wintel%'"),
  };
  console.log(`expected from SQL: findings(Max North)=${EXPECT.findingsMaxNorth} assets(Max North)=${EXPECT.assetsMaxNorth} assets(Wintel)=${EXPECT.assetsWintel}`);

  const count = async (url, re) => {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    const txt = await page.evaluate(() => document.body.innerText.replace(/,/g, ''));
    const m = txt.match(re);
    return m ? parseInt(m[1], 10) : -1;
  };
  const FIND = /([0-9]+)\s+findings? match/;
  const ASSET = /([0-9]+)\s+assets? in the inventory/;

  console.log('\nvulnerability list');
  const n1 = await count(`${BASE}/vulnerabilities/?search=Max+North&lifecycle=all`, FIND);
  (n1 === EXPECT.findingsMaxNorth) ? ok('owner name finds that person\'s findings', `${n1}`)
    : bad('owner name finds findings', `got ${n1}, sql says ${EXPECT.findingsMaxNorth}`);

  // Read the Owner cell itself, not the whole row: the vulnerability title
  // is long enough to push the owner past any sensible truncation.
  const owners = await page.evaluate(() => {
    const hdr = [...document.querySelectorAll('thead th')].map(t => t.innerText.trim());
    const i = hdr.findIndex(h => /owner/i.test(h));
    return [...document.querySelectorAll('tbody tr')].map(r => ((r.cells[i] || {}).innerText || '').trim());
  });
  const allMax = owners.length > 0 && owners.every(o => /Max North/.test(o));
  allMax ? ok('every row on screen is that owner', `${owners.length} rows checked`)
         : bad('every row is that owner', [...new Set(owners)].slice(0, 3).join(' | '));

  console.log('\nassets list');
  const a1 = await count(`${BASE}/assets/?search=Max+North&life=all`, ASSET);
  (a1 === EXPECT.assetsMaxNorth) ? ok('owner name finds their assets', `${a1}`)
    : bad('owner name finds their assets', `got ${a1}, sql says ${EXPECT.assetsMaxNorth}`);

  const a2 = await count(`${BASE}/assets/?search=Wintel&life=all`, ASSET);
  (a2 === EXPECT.assetsWintel) ? ok('team name matches unassigned kit too', `${a2}`)
    : bad('team name matches', `got ${a2}, sql says ${EXPECT.assetsWintel}`);

  console.log('\nwhat already worked still works');
  // A hostname read out of the estate, so this survives a re-import too.
  const host = execSync("echo \"SELECT hostname FROM vh_vulnhub_assets WHERE hostname <> '' LIMIT 1\" | /srv/vulnhub/q.sh", { encoding: 'utf8' })
    .trim().split('\n').pop().trim();
  const h = await count(`${BASE}/assets/?search=${encodeURIComponent(host)}&life=all`, ASSET);
  (h >= 1) ? ok('hostname still matches', `${h}`) : bad('hostname still matches', `${h}`);

  const ip = await count(`${BASE}/vulnerabilities/?search=192.168.0.153&lifecycle=all`, FIND);
  (ip > 0) ? ok('an IP now matches on the vulnerability list too', `${ip} findings`) : bad('IP matches on vuln list', `${ip}`);

  const cve = await count(`${BASE}/vulnerabilities/?search=libcurl&lifecycle=all`, FIND);
  (cve > 0) ? ok('vulnerability title still matches', `${cve}`) : bad('vulnerability title still matches', `${cve}`);

  const none = await count(`${BASE}/vulnerabilities/?search=zzzznotathing&lifecycle=all`, FIND);
  (none === 0) ? ok('a term that matches nothing returns nothing', '0') : bad('nonsense returns nothing', `${none}`);

  console.log('\nemail and UPN, for pasting out of a ticket');
  /*
   * Read a real address out of the database at run time rather than writing
   * one into this file. Staff addresses are production PII; a test fixture in
   * the repo is exactly the shared location they must not land in. It is used
   * and never printed -- only the count it produces is.
   */
  const email = execSync(
    `echo "SELECT email FROM vh_vulnhub_people WHERE display_name LIKE '%Max North%' AND email <> '' LIMIT 1" | /srv/vulnhub/q.sh`,
    { encoding: 'utf8' }
  ).trim().split('\n').pop().trim();

  if (!/@/.test(email)) {
    bad('found an address to test with');
  } else {
    const e1 = await count(`${BASE}/vulnerabilities/?search=${encodeURIComponent(email)}&lifecycle=all`, FIND);
    (e1 === EXPECT.findingsMaxNorth) ? ok('an email address finds that person\'s findings', `${e1}`)
                : bad('email address finds findings', `got ${e1}, expected ${EXPECT.findingsMaxNorth}`);

    const local = email.split('@')[0];
    const e2 = await count(`${BASE}/assets/?search=${encodeURIComponent(local)}&life=all`, ASSET);
    (e2 === EXPECT.assetsMaxNorth) ? ok('a partial address works too', `${e2} asset`)
      : bad('partial address works', `got ${e2}, sql says ${EXPECT.assetsMaxNorth}`);
  }

  console.log('\nsearch survives Apply, and exports');
  await page.goto(`${BASE}/vulnerabilities/?search=Max+North&lifecycle=all`, { waitUntil: 'networkidle' });
  await Promise.all([ page.waitForNavigation({ waitUntil: 'networkidle' }), page.click('form.vh-filters button:has-text("Apply")') ]);
  const kept = await page.evaluate(() => document.querySelector('input[name="search"]').value);
  (kept === 'Max North') ? ok('search term survives Apply', kept) : bad('search survives Apply', kept);

  const csv = await page.evaluate(async () => {
    const f = document.querySelector('form.vh-export__panel');
    const q = new URLSearchParams();
    for (const el of f.elements) {
      if (!el.name) continue;
      if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) continue;
      if (el.type === 'submit' || el.type === 'button') continue;
      q.append(el.name, el.value);
    }
    const t = await (await fetch(f.getAttribute('action') + '?' + q.toString(), { credentials: 'same-origin' })).text();
    const shown = document.body.innerText.replace(/,/g, '').match(/([0-9]+)\s+findings? match/);
    return { rows: t.trim().split('\n').length - 1, listed: shown ? parseInt(shown[1], 10) : -1 };
  });
  (csv.rows === csv.listed && csv.rows === EXPECT.findingsMaxNorth) ? ok('the export holds exactly that owner\'s findings', `${csv.rows} rows`)
                                            : bad('export matches the searched list', `csv ${csv.rows}, list ${csv.listed}`);

  console.log('\nthe placeholder says so');
  await page.goto(`${BASE}/vulnerabilities/`, { waitUntil: 'domcontentloaded' });
  const ph1 = await page.getAttribute('form.vh-filters input[name="search"]', 'placeholder');
  await page.goto(`${BASE}/assets/`, { waitUntil: 'domcontentloaded' });
  const ph2 = await page.getAttribute('form.vh-filters input[name="search"]', 'placeholder');
  (/owner/i.test(ph1) && /owner/i.test(ph2)) ? ok('both placeholders mention owner', `"${ph1}" / "${ph2}"`)
                                             : bad('placeholders mention owner', `"${ph1}" / "${ph2}"`);

  errs.length ? bad('console clean', errs.slice(0, 2).join(' | ')) : ok('console clean');
  console.log(`\n${pass}/${pass + fail} passed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})();
