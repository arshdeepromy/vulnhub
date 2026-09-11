# Performance

Measured 2026-09-10, after a report that the portal was "so slow". It was, in
bursts, and the reason was not the application.

## What the symptom actually was

Read out of the browser's own navigation timing on a live Vulnerabilities tab:

```
request_to_first_byte : 16458 ms
html_download         :     4 ms
resources             :    64, 14 KB total, all from cache, ~0 ms
protocol              : h3
```

Sixteen and a half seconds waiting for the server to produce the HTML, and
essentially nothing else. Not CSS, not JavaScript, not image weight, not the
Cloudflare tunnel. The same page measured 322 ms an hour later.

That gap is the whole story: the stack was not slow, it **collapsed under
contention**, and four things made it fragile.

---

## 1. MariaDB had a 128 MB cache in front of a 491 MB table

`innodb_buffer_pool_size` was 128 MB — the stock default, never tuned.

| | |
|---|---|
| `vh_vulnhub_findings` | 491 MB data + indexes |
| whole database | 540 MB |
| buffer pool | **128 MB** |

The hot table was roughly four times the cache in front of it, so any scan
evicted the pool and went back to disk: **20.3 million disk reads, about
325 GB**, in three days of uptime. The buffer pool hit rate was 97.56%, which
reads fine and is actually poor — InnoDB wants 99.9%+.

`mariadbd` was also found with **55 MB paged out to swap**, because the
container was capped at 1 GB while the host ran at `vm.swappiness = 60` with
3.4 GB free.

**Fixed** in `conf/mysql/vulnhub.cnf`: pool raised to 1536 M (the whole
database now fits in RAM, with room), container limit 1 g → 3 g, swappiness
60 → 10, and the pool is dumped at shutdown and reloaded at startup so a
deploy does not hand the first person through the door a cold cache.

The slow query log was also **off**, so nothing that took seconds was ever
recorded. It is on now at `long_query_time = 1`, writing to
`db/slow.log`.

### What this alone fixed

Searching `bc` on the vulnerability list — a very plausible term here, where
every hostname begins `bchyb` or `aws-bc-`:

```
before  12,777 ms
after      728 ms
```

Seventeen times faster, with no application change at all. That matters,
because the same slowness had previously been diagnosed as a query-shape
problem (an `OR` across two indexed columns that MySQL will not index-merge —
see FILTERS.md). The query shape is real, but it was never the binding
constraint: it was disk I/O from a pool too small to hold the table. A
complement-inversion rewrite of that query changed the timings *not at all*;
resizing the buffer pool changed them by 17x.

Worth remembering as a general lesson: the clever fix measured nothing, the
boring one measured everything.

---

## 2. Redis was running and doing nothing at all

```
DBSIZE                    0
total_commands_processed  1
object-cache.php          absent
phpredis extension        not installed in the web image
```

The container has been up for days serving no purpose. WordPress has no
persistent object cache, so every page re-reads options, transients and user
meta from MySQL — pages run **162–207 queries each**.

**Not yet fixed.** It needs `phpredis` in the web image (a rebuild) plus a
drop-in and `WP_REDIS_*` config. Worth doing, but be honest about the size of
the prize: DB time is only 34–166 ms of a 150–280 ms page, so this buys
smoothness and headroom under load, not a step change. Do it when there is a
window for an image rebuild.

---

## 3. Apache was on stock prefork defaults, wrong in both directions

```
StartServers          5
MinSpareServers       5
MaxSpareServers      10
MaxRequestWorkers   150
```

Too few and too many at once. Idle workers get reaped to ten, so a burst
queues behind ten processes while Apache forks more — and with mod_php each
fork is a ~50 MB PHP process. That is the shape behind a 250 ms page taking
sixteen seconds when several requests arrive together.

At the other end, 150 workers at ~50 MB is 7.5 GB against a 2 g container
limit; the ceiling could never be reached, it would OOM first. The database
also caps at 151 connections and prefork opens one per worker.

**Fixed** in `conf/apache/vulnhub-mpm.conf`: a real floor of warm workers
(`StartServers 16`, `MinSpareServers 12`), and a ceiling the container can
genuinely hold (`MaxRequestWorkers 40`), plus a short keep-alive timeout so a
tunnel connection does not pin a worker doing nothing.

---

## 4. VulnHub is a guest on a busy box with no reservation

Load was 7.4 on 16 cores while measuring, with `guacd` at 175%, the invoicing
app at 53% and NTFS media mounts at 18%. Nothing guarantees VulnHub any CPU or
memory share.

**Not fixed** — it is a policy decision, not a bug. If the portal becomes
something people depend on, give its containers `cpus` and `mem_reservation`
so a media transcode cannot starve it.

---

## Where it landed

Through the tunnel, at the public hostname:

| page | median TTFB |
|---|---|
| dashboard | 226 ms |
| vulnerabilities | 361 ms |
| assets | 349 ms |
| search `bc` | 728 ms |

Under real concurrency, measured with parallel `curl` against localhost (a
browser cannot measure this: Chrome caps a host at six connections, which
produced a fake 4.1 s tail in an early run of this very test):

| concurrency | median | max | throughput |
|---|---|---|---|
| 1 | 0.10 s | 0.10 s | — |
| 8 | 0.10 s | 0.12 s | 18.6 req/s |
| 16 | 0.17 s | 0.26 s | 24.6 req/s |
| 24 | 0.24 s | 0.71 s | 24.0 req/s |

No non-200s at any level.

---

## How to check this again

```sh
# is the pool holding the working set?
echo "SELECT (SELECT variable_value FROM information_schema.global_status
  WHERE variable_name='Innodb_buffer_pool_reads') AS disk_reads,
  (SELECT variable_value FROM information_schema.global_status
  WHERE variable_name='Innodb_buffer_pool_read_requests') AS logical_reads" | ./q.sh

# what has been slow lately?
tail -50 db/slow.log

# concurrency, honestly (not through a browser)
# log in first, export the cookie, then fire N parallel curls
```

If a page is slow again, get the browser's `responseStart - requestStart`
before assuming anything. It separates "the server was slow" from "the network
or the assets were slow" in one number, and those have completely different
causes.

