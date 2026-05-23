# ADD BELOW:
# log = logging.getLogger("phishnet")

SCRIPT_ROOT = Path(__file__).resolve().parent
ACTIVE_DOMAINS_FILE = SCRIPT_ROOT / "active_domains.txt"


# ADD BELOW load_extra_urls()

def load_active_domains() -> set[str]:
    """
    Automatically load URLs/domains from active_domains.txt
    located in the same directory as collector.py.
    """

    if not ACTIVE_DOMAINS_FILE.exists():
        log.warning(
            "active_domains.txt not found in script root: %s",
            ACTIVE_DOMAINS_FILE,
        )
        return set()

    urls: set[str] = set()

    try:
        for raw in ACTIVE_DOMAINS_FILE.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():
            line = raw.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            line = _ensure_scheme(line)

            if _is_valid_url(line):
                urls.add(_normalize(line))

        log.info(
            "Loaded %d URLs from active_domains.txt",
            len(urls),
        )

    except Exception as exc:
        log.error("Failed loading active_domains.txt: %s", exc)

    return urls


# REPLACE _kit_save() WITH THIS

def _kit_save(content: bytes, zip_url: str, output_dir: str) -> str:
    """
    Save phishing kit archives into a structured directory layout.
    """

    parsed = urlparse(zip_url)
    hostname = parsed.netloc.replace(":", "_")

    host_dir = Path(output_dir) / hostname
    host_dir.mkdir(parents=True, exist_ok=True)

    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", parsed.path.strip("/"))

    if not filename:
        filename = "index"

    if "." not in Path(filename).name:
        filename += ".zip"

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    final_name = f"{timestamp}_{filename}"

    dest = host_dir / final_name

    if not dest.exists():
        dest.write_bytes(content)

    return str(dest)


# REPLACE _process_url() WITH THIS

def _process_url(
    url: str,
    ua_cfg: dict,
    crawl_cfg: dict,
    do_kit_hunt: bool,
    kit_dir: str,
    ipinfo_token: str = "",
    kit_extensions: list[str] | None = None,
) -> tuple[str, dict]:

    kit_data = {}

    if do_kit_hunt:
        log.info("  Hunting kit for %s", url)

        kit_data = find_phishing_kit(
            url,
            crawl_cfg,
            kit_dir,
            kit_extensions,
        )

        if kit_data.get("kitphishr_status") != "success":
            log.debug("  No kit found for %s — continuing crawl", url)

    ua = pick_ua(ua_cfg)

    log.info("  Crawling %s  (UA: %s)", url, ua[:60])

    crawl_data = crawl_url(url, ua, crawl_cfg, ipinfo_token)

    if do_kit_hunt:
        crawl_data.update(kit_data)

    return url, crawl_data


# INSIDE run_collection()
# AFTER:
# log.info("Total unique URLs collected from feeds: %d", len(all_urls))

active_domain_urls = load_active_domains()

if active_domain_urls:
    all_urls.update(active_domain_urls)
    log.info(
        "Total URLs after active_domains merge: %d",
        len(all_urls),
    )


# INSIDE run_collection()
# REPLACE THIS:
#
# kit_found = crawl_data.get("kitphishr_status") == "success"
# if kit_found:
#
# WITH:

kit_found = crawl_data.get("kitphishr_status") == "success"

# Save every processed URL
url_id, _ = db_insert_url(conn, result_url, now)
db_insert_crawl(conn, url_id, crawl_data)

if kit_found:
    if urlscan_key:
        crawl_data.update(submit_urlscan(
            result_url,
            urlscan_key,
            urlscan_visibility,
            urlscan_tags,
        ))

    kit_hits.append({
        "url": result_url,
        "ip_address": crawl_data.get("ip_address"),
        "page_title": crawl_data.get("page_title"),
        "urlscan_result_url": crawl_data.get("urlscan_result_url"),
    })

    log.info(
        "[%d/%d] KIT FOUND — saved %s  http=%s  ip=%s  title=%s",
        done,
        total,
        result_url,
        crawl_data.get("http_status", "-"),
        crawl_data.get("ip_address", "-"),
        (crawl_data.get("page_title") or "-")[:60],
    )
else:
    log.info("[%d/%d] processed %s", done, total, result_url)


# CREATE THIS FILE BESIDE collector.py
# active_domains.txt

# Active phishing domains
example.com
https://evil-domain.tld/login
http://phish.example/update
