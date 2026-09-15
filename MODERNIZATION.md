# barnyard2 on Debian 13 — audit and modernisation notes

Written against commit `6387bf6` (upstream `firnsy/barnyard2`, unmaintained
since 2013), for a Snort 3 → barnyard2 → MySQL → Snorby pipeline.

Everything below was verified by building and running the code in a stock
`debian:13` container, not by inspection alone.

---

## 1. Why it would not build

Two dependencies are simply gone from Debian 13, and `configure` checked for
neither of them, so both surfaced as raw compiler errors part-way through
`make`:

| Dependency | Status on Debian 13 | Resolution |
|---|---|---|
| `libdaq` (`daq.h`, `sfbpf_dlt.h`) | Not packaged at all. Snort 2 and its DAQ were removed. | Dropped. barnyard2 never opened a DAQ module or linked `libdaq`; it only ever used the `DAQ_PktHdr_t` type and six `DLT_*` constants. These now live in the bundled `src/daq_compat.h`, used automatically when the system headers are absent. |
| `libdnet` (`dnet.h`) | Shipped as **`libdumbnet-dev`** with the header renamed to `dumbnet.h`, to avoid clashing with DECnet's libdnet. | `decode.c` already had a `HAVE_DUMBNET_H` branch — `configure.ac` just never defined it. Detection added. |

Even with both headers present, GCC 14 rejected the build outright. Two
diagnostics that were warnings for the last two decades are now errors by
default:

* `DecodePacket()` **had no prototype anywhere in the tree**, so `spooler.c`
  called it through an implicit declaration (`-Werror=implicit-function-declaration`).
* `DecodePacket()` was *defined* as taking `const struct DAQ_PktHdr_t *`.
  `DAQ_PktHdr_t` is a typedef, not a struct tag, so that declared a brand-new
  incomplete type and every forwarded call mismatched
  (`-Werror=incompatible-pointer-types`).

Underneath that was a genuine type confusion: `spooler.c` built a
`struct pcap_pkthdr` on the stack and passed it to code that declared the
parameter as `DAQ_PktHdr_t *`. It worked only because the two structs happen
to share a `{struct timeval; uint32_t; uint32_t}` prefix on Linux/amd64 —
and the plugin in `spo_log_tcpdump.c` handed a `DAQ_PktHdr_t` straight to
`pcap_dump()`, relying on the same coincidence when writing pcap files.

Also modernised: `AM_CONFIG_HEADER`, `AC_PROG_LIBTOOL` and `AC_PROG_CC_STDC`
(all removed in current autoconf), and the Linux-only
`extra_incl="-I/usr/include/pcap"` hack, which has not matched libpcap's
layout for many years.

## 2. Bugs fixed

### Event cache dropped its entire contents — `spooler.c`

`spoolerEventCacheClean()` purges one used event once the cache exceeds
`event_cache_size`. When the purge candidate happened to be the list head it did:

```c
if (ernCandidate == spooler->event_cache)
    spooler->event_cache = NULL;        /* rest of the list is now unreachable */
```

Every remaining node was leaked, and with it the event→packet correlation
state. `events_cached` was only decremented by one, so the counter stayed
permanently above the threshold and the cache thrashed from then on. On a
long-running sensor this is an unbounded leak plus alerts landing in Snorby
without their packet. Now unlinks the head only.

### Out-of-bounds stack write from database content — `spo_database_cache.c`

`u_int32_t sigRefArr[MAX_REF_OBJ]` (valid indices `0..254`) was guarded with
`if (ref_seq > MAX_REF_OBJ) FatalError(...)`, so `ref_seq == 255` passed the
check and wrote one element past the end. `ref_seq` comes from the
`sig_reference` table, and one use had **no bounds check at all**. Guards
corrected to `>=`, and the unchecked read now bounded.

### Only 1/4 of an array cleared — `spo_database_cache.c`

```c
memset(sigRefArr, '\0', MAX_REF_OBJ);   /* 255 bytes of a 1020-byte array */
```

Elements 64–254 kept "already seen" flags from the previous signature, so
signature references were silently skipped when writing `sig_reference` rows —
i.e. missing reference links in Snorby. Now `sizeof(sigRefArr)`.

### SQL escaping bypassed for one-character strings — `spo_database.c`

```c
if ((from_length = strlen(from)) == 1)
    return 0;                            /* "nothing to escape" */
```

Off by one: a *one-character* string was returned unescaped, so a lone `'` or
`\` reached the query verbatim. Reachable from packet payload when the
database output is configured with `encoding ascii` and `detail full` — a
single-byte payload of `'` is enough. Changed to `== 0`.

### Unvalidated record length from the spool file — `spi_unified2.c`, `spooler.c`

`Unified2ReadRecord()` took the 32-bit length straight off disk and passed it
to `SnortAlloc()`. A truncated or corrupt file — Snort killed mid-write is the
common case — could request up to 4 GB, which `SnortAlloc()` turns into a
`FatalError` and exit.

Worse, `spoolerProcessRecord()` then cast the buffer to `Unified2Packet` and
fed `packet_length` to the decoders as `caplen` **without checking it against
the record it actually read**, so a record claiming more packet data than it
contains walked the decoders off the end of the heap buffer.

Now: records are rejected outside `0 < len <= UNIFIED2_MAX_RECORD_LEN` (1 MB),
records too short to contain the struct being cast onto them are skipped, and
`packet_length` must fit inside the record. Verified against deliberately
malformed files — all four cases are now reported and skipped instead of
crashing or over-reading.

### Read past the end of a directory entry — `spooler.c`

`FindNextExtension()` prefix-matched `filebase` then parsed
`d_name + filebase_len + 1`. For an entry named *exactly* `filebase`, that
index is one past the terminating NUL. Now requires the `.` separator, and
`errno` is reset before `strtoul()` so the `ERANGE` check is meaningful (it
was reading a stale `errno` from an unrelated call).

### Shell injection in the archive path — `util.c`

`Move()` fell back to `system("mv <source> <dest>")` with unquoted paths when
`link()` failed across filesystems. Replaced with `rename()` plus an explicit
copy-and-unlink. It also logged "Failed to archive" unconditionally — even
when the move had succeeded.

`ArchiveFile()` did `strrchr(filepath, '/') + 1` with no NULL check, so a
spool path with no directory component dereferenced `NULL + 1`.

### PostgreSQL escaping rewritten — `spo_database.c`

Two separate functions escape strings for the database, and both were wrong
for PostgreSQL.

`snort_escape_string()` handled MySQL and PostgreSQL in one shared branch,
applying **MySQL** backslash escaping to both. Since PostgreSQL 9.1
`standard_conforming_strings` defaults to `on`, so a backslash is an ordinary
character inside a normal string literal: the `\'` this produced emitted a
literal backslash and then *closed* the string, turning any quote in the input
into an injection point. PostgreSQL now has its own branch using
`PQescapeStringConn()`, which also applies the connection's client encoding.
This function escapes the sensor name, interface name and BPF filter, so the
input is config-controlled rather than attacker-controlled — but the queries
it built were malformed either way.

`snort_escape_string_STATIC()` — the high-volume path, used for signature
messages, class names, reference tags and packet payload — already called
`PQescapeStringConn()`, but:

* it passed `buffer_max_len`, the *destination* capacity, where the function
  expects the **length of the source string**;
* it never checked that the destination could hold the required `2n+1` bytes;
* it copied the escaped result back into the caller's buffer **without
  checking that it fit**. The MySQL path did check; the PostgreSQL path
  returned early and skipped it. Since escaping can double the length, this
  could overflow fixed-size fields such as `SigNode.message[SIG_MSG_LEN]`
  (255 bytes);
* it treated an empty escaped result as an error, and compared the error flag
  against `1` rather than non-zero.

The shared copy-back path had its own off-by-one: it tested
`strlen(to_start) > buffer_max_len` (no room for the terminator) and then
copied only `strlen(to_start)` bytes, omitting the terminator entirely. As the
escaped form is never shorter than the original, that left the caller's buffer
unterminated whenever any escaping actually happened.

### Startup segfault parsing the database options — `spo_database.c`

`ParseDatabaseArgs()` reads the option list with two `strtok()` calls whose
delimiter sets disagree: the top of the loop splits on `" ="`, but the bottom
advanced with `"="` alone. Everything following the last `key=value` pair
therefore arrived as a single token with **no value**, and the `NULL` was
passed straight to `strncasecmp()`.

In practice that means a line such as

    output database: log, mysql, user=x password=y dbname=z host=h detail full

**segfaults at startup** — `detail full` becomes one token and `a1` is `NULL`.
Comma-separated options fared no better: the original silently failed to find
`dbname` and exited with "must enter database name". Only space-separated
`key=value` pairs with nothing trailing ever worked, which is exactly what the
shipped examples in `etc/barnyard2.conf` show, so this went unnoticed.

The loop now advances on `" ="` like its top, and a missing value is reported
as a configuration error instead of dereferencing `NULL`. Verified: the
original crashes on the config above, the fixed build parses it.

### Debug builds never linked — `spo_database_cache.c`

`glsl()` was defined as a bare `inline` with no `static` and no external
definition. Under C99/C11 that is an inline definition only, so any call the
compiler chose not to inline was left unresolved. The build succeeded purely
because `-O2` inlined all eight call sites; at `-O0` it failed with
`undefined reference to 'glsl'`, which is why nobody could build barnyard2
with debug symbols. Now `static inline`.

### Broken overflow check and overlapping copy — `util.c`

`BY2Strtoul()` tested `strtoul()`'s result against `LONG_MAX`/`LONG_MIN`, which
it never returns — overflow is reported as `ULONG_MAX` — and read `errno`
without clearing it first, so the check was both dead and prone to firing on a
stale `errno`. `string_sanitize_character()` used `memcpy()` on overlapping
regions, which is undefined, and wrote its terminator one byte past the
shortened string.

### Other fixed

* `util.c` `SetUidGid()` — `free(username)` then passed `username` to
  `FatalError()` (use-after-free read).
* `spooler.c` `ProcessBatch()` — never called `UnRegisterSpooler()`, leaving a
  dangling pointer in `barnyard2_conf->spooler` after the spooler was freed.
* `spooler.c` `ProcessContinuous()` — tested `FindNextExtension() == -1` for
  errors, but that function returns 2/3. A spool directory that became
  unreadable was silently treated as "no new data", so barnyard2 would sit in
  its 1-second sleep loop forever instead of reporting the problem.
* `spo_alert_fwsam.c` — `if(p>buf);` (stray semicolon) made a self-copy
  unconditional; two `strcpy()` calls copied overlapping buffers, which is
  undefined. All three now `memmove()`.
* `spo_log_tcpdump.c` — converts the DAQ header to a real `struct pcap_pkthdr`
  before calling `pcap_dump()`.
* `mstring.c` — `mSplit()` returned its on-stack scratch buffer on paths where
  an invariant the compiler could not verify said otherwise. It now always
  returns a fresh heap array.
* `spo_database.c` — `if ((&p->tcp_options[i]) && ...)` tested the address of
  an array element, which is never NULL. The intent was
  `p->tcp_options[i].data != NULL`, which is what it now checks.
* `sf_ip.c` — `calloc(sizeof(sfip_t), 1)` had its arguments transposed.
* `spo_alert_arubaaction.c` — `strncpy(dst, src, strlen(src))` copied no
  terminator (harmless, since `SnortAlloc()` is `calloc()`-backed, but it now
  copies it explicitly).

## 3. Found but deliberately **not** changed

These are real, but fixing them needs a decision I should not make alone.

### Event IDs truncated to 16 bits — `spooler.c:739`

```c
uint32_t event_id = 0x0000ffff & ntohl(((Unified2CacheCommon *)...)->event_id);
```

Event/packet correlation keys on `(event_id & 0xffff, event_second)`. Two
distinct events in the cache in the same second whose IDs differ only above
bit 16 will collide, and the packet gets attached to the wrong alert — a
wrong packet displayed in Snorby, not a crash.

It needs >65536 events within one `event_cache_size` window, so it is a
high-event-rate problem. I left it because the mask is deliberate — it works
around historical disagreement between Snort's event and packet records about
the upper bits — and **removing it should be validated against the unified2
output your Snort 3 build actually produces** before trusting it.

### MySQL escaping is hand-rolled

The same function reimplements `mysql_real_escape_string()`. It is not
charset-aware (a real issue only for multi-byte charsets such as GBK/SJIS) and
it is wrong if the server runs in `NO_BACKSLASH_ESCAPES` mode. Using
`mysql_real_escape_string()` on the live connection would fix both. Low risk
in your setup; flagged for completeness.

### `UNIFIED2_EXTRA_DATA` records are discarded

`spoolerProcessRecord()` handles the type only by advancing the waldo. Snort 3
emits extra-data records (HTTP URI/hostname, etc.); none of it reaches the
database. That is a missing feature rather than a bug, but it is why some
Snorby fields stay empty.

### `MYSQL_OPT_RECONNECT`

Deprecated in MySQL 8.0.34 and removed in MySQL 9. Debian 13 links MariaDB
Connector/C (`libmariadb3`), which still supports it, so the build is fine —
but the option will need replacing with explicit reconnect handling if you
ever move to the Oracle client.

### Behaviour change worth knowing about

The overflow checks in the `sid-msg.map` / `gen-msg.map` parsers could never
fire — `t_sn.id` and friends are `uint32_t`, so the value was truncated before
being compared against 64-bit `ULONG_MAX`. Malformed map files have therefore
never been diagnosed, and a non-numeric field silently became 0.

They are now parsed properly, but a bad field logs a **warning and uses 0**
rather than calling `FatalError`, deliberately: a map file that has been
tolerated for years should not suddenly stop barnyard2 from starting. Check
your logs for `WARNING: map file:` after upgrading, and tighten it to fatal if
you would rather fail loudly.

## 4. Compiler warnings

The tree now builds with **zero warnings at `-Wall`** on GCC 14 (with both the
MySQL and PostgreSQL plugins enabled). Everything in that set was either a real
defect — listed above — or dead code, with two exceptions that are marked
explicitly rather than silently changed:

* `spo_alert_fwsam.c`'s `lastbsp[]` is written but never read, because the leg
  of the duplicate-block check that compared the source port is commented out
  upstream. Restoring it would change what the plugin blocks, so it carries a
  `BY2_UNUSED` marker and a note instead.
* The eight intentional switch fall-throughs (the Twofish key-size cascade,
  the TCP option decoder, three option parsers) now use a `BY2_FALLTHROUGH`
  marker. GCC only recognises a narrow set of comment spellings at the level
  `-Wextra` turns on, and the existing "fall thru" comments did not qualify.

Under `-Wall -Wextra` **137 warnings remain, all benign**, and I left them:

| Class | Count | Why |
|---|---:|---|
| `-Wunused-parameter` | 120 | Inherent to the plugin ABI: every output plugin's callback takes `(Packet *, void *, uint32_t, void *)` and most ignore some of them. Silencing these means annotating ~120 parameters across every plugin — large diff, no behavioural benefit, and it fights the architecture. |
| `-Wsign-compare` | 17 | `int` loop indices compared against `uint32_t` row/array counts, and signature-id comparisons. All the values involved are small and non-negative. |

The one `-Wsign-compare` hit that *was* a real defect — `BY2Strtoul()` comparing
an `unsigned long` against `LONG_MAX`/`LONG_MIN` — is fixed and described above.

If you want the package build to stay quiet, `debian/rules` passes `-Wall`
(not `-Wextra`), so it is warning-free as shipped.

## 5. Verification

* Builds clean on stock `debian:13` — no libdaq, zero warnings at `-Wall`.
* Byte-identical `alert_csv` output to the original code on a valid unified2
  file (3 events + 3 correlated packets), confirming no behavioural regression
  in decode, correlation or the text output plugins.
* Malformed unified2 inputs (3 GB length, zero length, undersized record,
  overstated `packet_length`) are reported and skipped; the original either
  aborted or over-read.
* `.deb` installs, creates the `barnyard2` system user, registers both
  conffiles, installs the systemd unit, and the binary runs.
* Against a live MariaDB 11 with the shipped `create_mysql` schema: the fixed
  build parses `detail full encoding ascii` and synchronises the signature
  cache where the original segfaults in the option parser.

**Not fully exercised:** I did not get a complete event written to the
database. With a hand-built unified2 file both the original and the fixed
build stop at the same point in `dbProcessEventInformation()`, so the
behaviour is unchanged — but that means the insert path, and therefore the
escaping changes, were **not** validated end to end against a real server.
The likely cause is a mismatch in my synthetic file (classification id and
signature revision that do not resolve against the map files) rather than a
barnyard2 defect, but I did not chase it to ground. Worth a dry run against a
copy of your real spool file before this goes near production.

One related discovery: the `-C`, `-S` and `-G` command-line flags did not
populate the database cache, while the equivalent `config classification_file:`,
`config sid_file:` and `config gen_file:` directives in `barnyard2.conf` did.
Use the config-file form.

## 6. Packaging

`./build-deb.sh --docker` builds a Debian 13 package in a container (use this
if the host is not trixie); `./build-deb.sh` builds natively. Output lands in
`dist/`.

The package installs the binary, a systemd unit with a hardened sandbox,
`/etc/default/barnyard2` for the spool paths, the MySQL/PostgreSQL schemas
under `/usr/share/barnyard2/schemas/`, and a `barnyard2` system user. Edit
`/etc/default/barnyard2` to point at Snort's unified2 directory and prefix,
then `systemctl enable --now barnyard2`.

## 7. The larger point

barnyard2 has been unmaintained since 2013 and Snort 3's own `alert_json` /
`alert_full` outputs, or a Logstash/Filebeat pipeline, cover most of what this
was for. If Snorby is the only reason it is still in the path — Snorby is
itself unmaintained (last release 2015, Rails 3) — that is worth revisiting
separately. Nothing above changes that; it just makes the current pipeline
build and run correctly on Debian 13.
