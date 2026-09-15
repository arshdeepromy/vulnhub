const VH_ROOT = process.env.VULNHUB_ROOT || require('path').resolve(__dirname, '..');
/*
 * Does the Elementor side of VulnHub actually work in the editor?
 *
 * The front end can be perfect while the editor is broken -- a widget whose
 * controls throw, a category that never registers, a panel that renders
 * nothing. This opens the real Elementor editor on the seeded header and on a
 * seeded page and checks the things somebody laying out a page depends on.
 *
 * Run without sudo: Playwright's browsers live in ~/.cache/ms-playwright.
 */
const { chromium } = require('playwright');
const fs = require('fs');

const BASE = 'http://localhost:8093';
const PASS = fs.readFileSync(VH_ROOT + '/.admin_pass', 'utf8').trim();

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

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await context.newPage();

  const problems = [];
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const t = m.text();
    // Elementor's own editor is noisy about third-party promos and about
    // fetches the licence server refuses in a sandbox. Neither is ours.
    if (/favicon|the-favicon|connect\.elementor|my\.elementor|Failed to load resource: the server responded with a status of 40/i.test(t)) return;
    problems.push(t);
  });
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));

  await page.goto(BASE + '/wp-login.php');
  await page.fill('#user_login', (process.env.VH_ADMIN_USER || 'admin'));
  await page.fill('#user_pass', PASS);
  await Promise.all([page.waitForNavigation(), page.click('#wp-submit')]);

  /*
   * VH_DOCS is an override, not a requirement. Without this fallback the
   * script silently navigated to "post=undefined&action=elementor" and then
   * spent sixty seconds waiting for an editor panel that was never coming --
   * a missing environment variable reported as a timeout, which costs
   * whoever runs it next a diagnosis it does not deserve.
   */
  let docs = JSON.parse(process.env.VH_DOCS || '{}');

  if (!Object.keys(docs).length) {
    try {
      docs = JSON.parse(
        require('child_process')
          .execSync(`${VH_ROOT}/wp.sh option get vulnhub_elementor_documents --format=json 2>/dev/null`)
          .toString()
          .trim()
      );
    } catch (e) {
      console.error('Could not read vulnhub_elementor_documents. Is the stack up?');
      process.exit(1);
    }
  }

  for (const [label, id] of Object.entries(docs)) {
    console.log('\n' + label + ' (post ' + id + ')');

    await page.goto(BASE + '/wp-admin/post.php?post=' + id + '&action=elementor', {
      waitUntil: 'domcontentloaded',
    });

    try {
      await page.waitForSelector('#elementor-editor-wrapper, #elementor-panel', { timeout: 60000 });
      ok('editor loaded');
    } catch (e) {
      bad('editor loaded', e.message);
      continue;
    }

    // The preview iframe is where our widgets actually render.
    const frame = await page
      .waitForSelector('#elementor-preview-iframe', { timeout: 60000 })
      .then((h) => h.contentFrame())
      .catch(() => null);

    if (!frame) {
      bad('preview iframe present');
      continue;
    }

    try {
      await frame.waitForSelector('.elementor-widget[data-widget_type^="vulnhub-"]', { timeout: 60000 });
      // The first widget appearing does not mean the document is finished --
      // Elementor renders elements as they arrive, and asserting here reported
      // a header with one widget in it.
      await page.waitForTimeout(2500);
      const kinds = await frame.$$eval('.elementor-widget[data-widget_type^="vulnhub-"]', (els) =>
        Array.from(new Set(els.map((e) => e.getAttribute('data-widget_type'))))
      );
      ok('VulnHub widgets render in the preview', kinds.length + ': ' + kinds.join(', '));

      // innerHTML, not textContent: the light/dark toggle is an icon button
      // with no text in it and is perfectly correct that way.
      const empty = await frame.$$eval('.elementor-widget[data-widget_type^="vulnhub-"]', (els) =>
        els
          .filter((e) => (e.querySelector('.elementor-widget-container')?.innerHTML || '').trim() === '')
          .map((e) => e.getAttribute('data-widget_type'))
      );

      if (empty.length) {
        bad('every widget drew something', 'empty: ' + empty.join(', '));
      } else {
        ok('every widget drew something');
      }
    } catch (e) {
      bad('VulnHub widgets render in the preview', e.message);
    }
  }

  // The panel: is the category there, and are all our widgets in it?
  console.log('\nthe widget panel');

  await page.goto(BASE + '/wp-admin/post.php?post=' + Object.values(docs)[0] + '&action=elementor', {
    waitUntil: 'domcontentloaded',
  });
  await page.waitForSelector('#elementor-panel', { timeout: 60000 });

  try {
    await page.click('#elementor-panel-header-add-button, [aria-label="Add Element"], .elementor-panel-header-add-button', { timeout: 20000 });
  } catch (e) {
    /* Some builds open on the elements panel already. */
  }

  try {
    await page.waitForSelector('#elementor-panel-category-vulnhub, .elementor-panel-category[data-category="vulnhub"]', { timeout: 30000 });
    ok('the VulnHub category is in the panel');

    const titles = await page.$$eval(
      '#elementor-panel-category-vulnhub .elementor-element-wrapper .title, .elementor-panel-category[data-category="vulnhub"] .title',
      (els) => els.map((e) => e.textContent.trim())
    );
    if (titles.length >= 12) {
      ok('every VulnHub widget is listed', titles.length + ' widgets');
    } else {
      bad('every VulnHub widget is listed', 'only ' + titles.length + ': ' + titles.join(', '));
    }
  } catch (e) {
    bad('the VulnHub category is in the panel', e.message);
  }

  /* ------------------------------------------------------------------
   * The estate table: headings must describe the column beneath them.
   *
   * They did not. Identifiers was spliced into the header array at index 5
   * while the body wrote it at 4, so CMDB/Intune/Tenable sat under "Coverage"
   * and "Covered" sat under "Identifiers". Both columns were full of real
   * data, which is exactly why nobody caught it by looking.
   * ------------------------------------------------------------------ */
  try {
    await page.goto(BASE + '/vulnhub-estate/', { waitUntil: 'networkidle', timeout: 90000 });

    const t = await page.evaluate(() => {
      const tbl = document.querySelector('.vh-table--estate');
      if (!tbl) return { err: 'estate table not found' };
      const ths = [...tbl.querySelectorAll('thead th')].map(e => e.innerText.trim().toLowerCase());
      const cells = [...tbl.querySelector('tbody tr').cells];
      const at = n => ths.indexOf(n);
      const txt = i => (cells[i] ? cells[i].innerText.replace(/\s+/g, ' ').trim() : '');
      const osTd = cells[at('operating system')];
      const nm = osTd && osTd.querySelector('.vh-os__name');
      return {
        cov: txt(at('coverage')),
        ids: txt(at('identifiers')),
        osLines: nm ? Math.round(nm.getBoundingClientRect().height / parseFloat(getComputedStyle(nm).lineHeight)) : -1,
        osFont: nm ? getComputedStyle(nm).fontSize : '',
        overflow: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth)
      };
    });

    if (t.err) { bad('estate table renders', t.err); }
    else {
      /* Identifiers are source names, coverage is a state word.
       *
       * No word boundaries in the pattern: the pills render adjacent with no
       * separator, so innerText is "CMDBIntuneTenable" -- one word, in which
       * \bCMDB\b cannot match. */
      /(CMDB|Intune|Tenable)/i.test(t.ids)
        ? ok('the Identifiers column holds identifiers', t.ids.slice(0, 32))
        : bad('Identifiers column holds identifiers', t.ids.slice(0, 40));

      (!/(CMDB|Intune|Tenable)/i.test(t.cov) && t.cov.length > 0)
        ? ok('the Coverage column holds a coverage state', t.cov.slice(0, 32))
        : bad('Coverage column holds a coverage state', t.cov.slice(0, 40));

      // The badge is a 24px icon chip in app.css and a readable two-line
      // layout in app-redesign.css, which Elementor pages do not load. If
      // this reads 9px again, that regression is back.
      (t.osFont === '13px' && t.osLines > 0 && t.osLines <= 2)
        ? ok('the OS name is readable, not folded into an icon chip', `${t.osLines} line(s) @ ${t.osFont}`)
        : bad('OS name is readable', `${t.osLines} line(s) @ ${t.osFont}`);

      (t.overflow === 0) ? ok('the estate page does not overflow sideways') : bad('no horizontal overflow', t.overflow + 'px');

      /* No icon may render at a size nobody asked for.
       *
       * These pages load app.css but not app-redesign.css, and an inline
       * <svg> carrying only a viewBox has no intrinsic size -- so an icon
       * sized solely by the missing layer expands to fill its container. The
       * widget export glyph did exactly that at 1102x1102, which is what
       * this asserts against. */
      const fat = await page.evaluate(() => [...document.querySelectorAll('svg')]
        .map(sv => ({ w: Math.round(sv.getBoundingClientRect().width),
                      h: Math.round(sv.getBoundingClientRect().height),
                      cls: (sv.getAttribute('class') || sv.parentElement.className || '').toString().slice(0, 30),
                      vb: sv.getAttribute('viewBox') || '' }))
        // charts are legitimately large; icons declare a 24-unit viewBox
        .filter(o => o.vb === '0 0 24 24' && (o.w > 64 || o.h > 64)));

      fat.length === 0
        ? ok('no icon has escaped its size')
        : bad('no icon has escaped its size', fat.map(o => `${o.cls} ${o.w}x${o.h}`).join(', '));

      /* The account menu's items.
       *
       * `.vh-account__menu` had card chrome from app.css and the kit re-homes
       * it inside the rail, but no stylesheet ever had a rule for the links
       * inside it -- so they rendered as bare inline anchors and read as one
       * word: "AdministrationSign out". */
      const acct = await page.evaluate(() => {
        const d = document.querySelector('details.vh-account');
        if (!d) return null;
        d.open = true;
        const links = [...d.querySelectorAll('.vh-account__menu a')];
        return {
          n: links.length,
          allBlock: links.every(a => getComputedStyle(a).display === 'block'),
          padded: links.every(a => parseFloat(getComputedStyle(a).paddingTop) >= 4),
          separated: links.every(a => a.getBoundingClientRect().height >= 24),
          marker: getComputedStyle(d.querySelector('summary')).listStyleType
        };
      });

      if (!acct) { bad('the account menu is present'); }
      else {
        (acct.n >= 1 && acct.allBlock && acct.padded && acct.separated)
          ? ok('account menu items are real menu items', `${acct.n} items, block, padded`)
          : bad('account menu items are real menu items', JSON.stringify(acct));

        (acct.marker === 'none')
          ? ok('no browser disclosure triangle on the account trigger')
          : bad('disclosure marker hidden', acct.marker);
      }
    }
  } catch (e) {
    bad('estate table checks', e.message);
  }

  console.log('\n' + passed + ' passed, ' + failed + ' failed');

  if (problems.length) {
    console.log('\nconsole/page errors:');
    Array.from(new Set(problems)).slice(0, 15).forEach((p) => console.log('  ' + p));
  } else {
    console.log('no console or page errors throughout');
  }

  await browser.close();
  process.exit(failed ? 1 : 0);
})();

