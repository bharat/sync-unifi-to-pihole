import os
import re
import time
import requests
import argparse
import logging
import atexit
from contextlib import contextmanager
from requests.packages.urllib3.exceptions import InsecureRequestWarning

try:
    from dotenv import load_dotenv
    load_dotenv('.env.local')
    load_dotenv('.env')
except ImportError:
    pass

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

CLOUDFLARE_MANAGED_COMMENT = "managed-by:sync-unifi-to-pihole"

_active_pihole_sessions = []

def setup_logging(log_level):
    """Configure logging based on the specified level."""
    level_map = {
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'trace': logging.DEBUG
    }

    level = level_map.get(log_level.lower(), logging.INFO)

    class LowercaseFormatter(logging.Formatter):
        def format(self, record):
            record.levelname = record.levelname.lower()
            return super().format(record)

    formatter = LowercaseFormatter('sync-udm-to-pihole: %(levelname)s: %(message)s')

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.setLevel(level)
    logger.addHandler(console_handler)

    logging.getLogger().setLevel(level)

def normalize_hostname(hostname):
    """
    Normalize hostname to conform to RFC 1123 (ISO hostname standards).

    Rules:
    - Only alphanumeric characters and hyphens
    - Cannot start or end with hyphen
    - Maximum 63 characters per label
    - Case insensitive (convert to lowercase)
    """
    if not hostname:
        return ""

    hostname = hostname.lower()
    hostname = re.sub(r'[^a-z0-9-]', '-', hostname)
    hostname = re.sub(r'-+', '-', hostname)
    hostname = hostname.strip('-')
    hostname = hostname[:63]
    hostname = hostname.rstrip('-')

    if not hostname or hostname[0].isdigit():
        hostname = f"device-{hostname}" if hostname else "device"

    return hostname

# ---------------------------------------------------------------------------
# UniFi
# ---------------------------------------------------------------------------

def fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password):
    """Fetch static DHCP leases from UniFi OS using REST API."""
    session = requests.Session()

    login_url = f"https://{unifi_ip}/api/auth/login"
    login_data = {
        "username": unifi_user,
        "password": unifi_password
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        login_response = session.post(
            login_url,
            headers=headers,
            json=login_data,
            verify=False,
            timeout=10
        )
        login_response.raise_for_status()

        api_url = f"https://{unifi_ip}/proxy/network/api/s/default/rest/user"
        api_response = session.get(api_url, headers=headers, verify=False, timeout=10)
        api_response.raise_for_status()

        data = api_response.json()
        if data.get("meta", {}).get("rc") != "ok":
            raise RuntimeError(f"API returned error: {data}")

        leases = []
        for user in data.get("data", []):
            if user.get("use_fixedip", False) and user.get("fixed_ip"):
                raw_hostname = user.get("name") or user.get("hostname")
                normalized_hostname = normalize_hostname(raw_hostname)

                lease = {
                    "ip": user.get("fixed_ip"),
                    "hostname": normalized_hostname,
                    "mac": user.get("mac")
                }
                if lease["ip"] and lease["hostname"]:
                    leases.append(lease)

        return leases

    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [401, 403]:
            raise RuntimeError(f"UniFi authentication failed: incorrect username or password for user '{unifi_user}'. Please check your UNIFI_USER and UNIFI_PASSWORD environment variables.")
        else:
            raise RuntimeError(f"Failed to fetch config from UniFi API: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to fetch config from UniFi API: {e}")

# ---------------------------------------------------------------------------
# Pi-hole
# ---------------------------------------------------------------------------

def logout_pihole(pihole_ip, sid):
    """Logout from Pi-hole v6.0 API to clean up the session."""
    if not sid:
        return

    logout_url = f"https://{pihole_ip}/api/auth"
    headers = {
        "accept": "application/json",
        "sid": sid
    }

    try:
        response = requests.delete(logout_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        logger.debug(f"Successfully logged out from Pi-hole")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Failed to logout from Pi-hole: {e}")

def cleanup_all_pihole_sessions():
    """Clean up all active Pi-hole sessions on exit."""
    global _active_pihole_sessions
    for pihole_ip, sid in _active_pihole_sessions:
        logger.debug(f"Cleaning up Pi-hole session on exit: {sid}")
        logout_pihole(pihole_ip, sid)
    _active_pihole_sessions.clear()

atexit.register(cleanup_all_pihole_sessions)

def authenticate_pihole(pihole_ip, pihole_password):
    """Authenticate with Pi-hole v6.0 API and return session ID."""
    auth_url = f"https://{pihole_ip}/api/auth"
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    try:
        response = requests.post(
            auth_url,
            headers=headers,
            json={"password": pihole_password},
            verify=False,
            timeout=10
        )
        response.raise_for_status()

        auth_data = response.json()
        session_info = auth_data.get("session", {})

        if not session_info.get("valid", False):
            raise RuntimeError("Pi-hole authentication failed: incorrect password. Please check your PIHOLE_PASSWORD environment variable.")

        sid = session_info.get("sid")
        if not sid:
            raise RuntimeError("Pi-hole authentication failed: no session ID returned")

        global _active_pihole_sessions
        _active_pihole_sessions.append((pihole_ip, sid))

        logger.debug(f"Successfully authenticated with Pi-hole")
        return sid

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            raise RuntimeError("Pi-hole authentication failed: incorrect password. Please check your PIHOLE_PASSWORD environment variable.")
        else:
            raise RuntimeError(f"Failed to authenticate with Pi-hole: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to authenticate with Pi-hole: {e}")

@contextmanager
def pihole_session(pihole_ip, pihole_password):
    """Context manager for Pi-hole sessions that ensures cleanup."""
    sid = None
    try:
        sid = authenticate_pihole(pihole_ip, pihole_password)
        yield sid
    finally:
        if sid:
            logout_pihole(pihole_ip, sid)
            global _active_pihole_sessions
            _active_pihole_sessions = [(ip, s) for ip, s in _active_pihole_sessions if s != sid]

def get_existing_pihole_dns_records(pihole_ip, sid):
    """Get existing DNS records from Pi-hole v6.0 API."""
    dns_url = f"https://{pihole_ip}/api/config/dns%2Fhosts"
    headers = {
        "accept": "application/json",
        "sid": sid
    }

    try:
        response = requests.get(dns_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()

        data = response.json()
        hosts = data.get("config", {}).get("dns", {}).get("hosts", [])

        existing_records = []
        for host_entry in hosts:
            parts = host_entry.strip().split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                existing_records.append((hostname, ip))

        return existing_records

    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to get existing DNS records from Pi-hole: {e}")

def sync_pihole(pihole_ip, pihole_password, domain, expected, dry_run=False):
    """Sync Pi-hole DNS records with expected set. Returns error count."""
    logger.info(f"Syncing {len(expected)} records to Pi-hole")

    with pihole_session(pihole_ip, pihole_password) as sid:
        existing_all = get_existing_pihole_dns_records(pihole_ip, sid)

        existing = set()
        for hostname, ip in existing_all:
            if hostname.endswith(f".{domain}"):
                existing.add((hostname, ip))

        logger.info(f"Found {len(existing)} existing DNS records for domain {domain}")

        to_add = expected - existing
        to_remove = existing - expected

        logger.info(f"Pi-hole sync plan: {len(to_add)} to add, {len(to_remove)} to remove")

        if dry_run:
            for fqdn, ip in sorted(to_add):
                logger.warning(f"Pi-hole: would add {fqdn} → {ip}")
            for fqdn, ip in sorted(to_remove):
                logger.warning(f"Pi-hole: would remove {fqdn} → {ip}")
            if not to_add and not to_remove:
                logger.warning("Pi-hole: already in sync, nothing to do")
            return 0

        headers = {"accept": "application/json", "sid": sid}
        added = removed = errors = 0

        for fqdn, ip in to_add:
            url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{ip}%20{fqdn}"
            try:
                response = requests.put(url, headers=headers, verify=False, timeout=10)
                response.raise_for_status()
                logger.info(f"Pi-hole: added {fqdn} → {ip}")
                added += 1
            except requests.exceptions.RequestException as e:
                logger.error(f"Pi-hole: failed to add {fqdn} → {ip}: {e}")
                errors += 1

        for fqdn, ip in to_remove:
            url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{ip}%20{fqdn}"
            try:
                response = requests.delete(url, headers=headers, verify=False, timeout=10)
                response.raise_for_status()
                logger.warning(f"Pi-hole: removed {fqdn} → {ip}")
                removed += 1
            except requests.exceptions.RequestException as e:
                logger.error(f"Pi-hole: failed to remove {fqdn} → {ip}: {e}")
                errors += 1

        logger.info(f"Pi-hole sync complete: {added} added, {removed} removed, {errors} errors")
        return errors

# ---------------------------------------------------------------------------
# Cloudflare
# ---------------------------------------------------------------------------

_CF_MAX_RETRIES = 3
_CF_BACKOFF_BASE = 2  # seconds

def cloudflare_request(method, url, headers, **kwargs):
    """Wrapper around requests with retry/backoff for transient Cloudflare errors."""
    last_exc = None
    for attempt in range(_CF_MAX_RETRIES):
        try:
            resp = requests.request(method, url, headers=headers, **kwargs)
            if resp.status_code >= 500:
                detail = resp.text
                try:
                    detail = resp.json().get("errors", resp.text)
                except Exception:
                    pass
                if attempt < _CF_MAX_RETRIES - 1:
                    wait = _CF_BACKOFF_BASE * (2 ** attempt)
                    logger.debug(
                        f"Cloudflare returned {resp.status_code}, retrying in {wait}s "
                        f"(attempt {attempt + 1}/{_CF_MAX_RETRIES}): {detail}"
                    )
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < _CF_MAX_RETRIES - 1:
                wait = _CF_BACKOFF_BASE * (2 ** attempt)
                logger.debug(
                    f"Cloudflare request failed, retrying in {wait}s "
                    f"(attempt {attempt + 1}/{_CF_MAX_RETRIES}): {e}"
                )
                time.sleep(wait)
            else:
                raise
    raise last_exc

def get_cloudflare_dns_records(api_token, zone_id, domain):
    """Fetch all A records under *.<domain> from Cloudflare."""
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    records = []
    page = 1
    while True:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        params = {"type": "A", "per_page": 500, "page": page}

        try:
            response = cloudflare_request("GET", url, headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                raise RuntimeError(f"Cloudflare API error: {data.get('errors')}")

            for record in data.get("result", []):
                name = record.get("name", "")
                if name.endswith(f".{domain}") and name != domain:
                    records.append(record)

            result_info = data.get("result_info", {})
            if page >= result_info.get("total_pages", 1):
                break
            page += 1

        except requests.exceptions.HTTPError as e:
            detail = ""
            try:
                detail = e.response.json().get("errors", e.response.text)
            except Exception:
                detail = e.response.text
            if e.response.status_code in [401, 403]:
                raise RuntimeError(
                    f"Cloudflare authentication failed. Check your CLOUDFLARE_API_TOKEN. ({detail})"
                )
            raise RuntimeError(f"Cloudflare API error ({e.response.status_code}): {detail}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to fetch DNS records from Cloudflare: {e}")

    return records

def sync_cloudflare(api_token, zone_id, domain, expected, dry_run=False):
    """
    Sync DNS A records to Cloudflare. Returns error count.

    Only records tagged with CLOUDFLARE_MANAGED_COMMENT are ever modified or
    deleted. Unmanaged records that conflict produce an error instead.

    Hosts with multiple A records (e.g. dual-homed devices) are handled
    correctly -- each (name, ip) pair is tracked independently.
    """
    logger.info(f"Syncing {len(expected)} records to Cloudflare")

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"

    cf_records = get_cloudflare_dns_records(api_token, zone_id, domain)
    logger.info(f"Found {len(cf_records)} existing A records under *.{domain} in Cloudflare")

    # Key by (name, ip) so multi-valued hosts are handled correctly
    managed = {}    # (name, ip) -> record dict
    unmanaged = {}  # (name, ip) -> record dict
    for rec in cf_records:
        key = (rec["name"], rec["content"])
        comment = rec.get("comment") or ""
        if CLOUDFLARE_MANAGED_COMMENT in comment:
            managed[key] = rec
        else:
            unmanaged[key] = rec

    logger.debug(f"Cloudflare: {len(managed)} managed, {len(unmanaged)} unmanaged records")

    added = removed = errors = 0

    # --- Adds ---
    for fqdn, ip in expected:
        if (fqdn, ip) in managed:
            logger.debug(f"Cloudflare: {fqdn} → {ip} already correct")
        elif (fqdn, ip) in unmanaged:
            logger.debug(f"Cloudflare: {fqdn} → {ip} exists (unmanaged), skipping")
        else:
            if dry_run:
                logger.warning(f"Cloudflare: would add {fqdn} → {ip}")
                added += 1
            else:
                try:
                    resp = cloudflare_request(
                        "POST", base_url, headers,
                        json={
                            "type": "A",
                            "name": fqdn,
                            "content": ip,
                            "ttl": 1,
                            "proxied": False,
                            "comment": CLOUDFLARE_MANAGED_COMMENT,
                        },
                        timeout=30,
                    )
                    resp.raise_for_status()
                    if not resp.json().get("success"):
                        raise RuntimeError(resp.json().get("errors"))
                    logger.info(f"Cloudflare: added {fqdn} → {ip}")
                    added += 1
                except requests.exceptions.RequestException as e:
                    logger.error(f"Cloudflare: failed to add {fqdn} → {ip}: {e}")
                    errors += 1

    # --- Removals (only managed records no longer in expected) ---
    for (name, ip), rec in managed.items():
        if (name, ip) not in expected:
            if dry_run:
                logger.warning(f"Cloudflare: would remove {name} → {ip}")
                removed += 1
            else:
                try:
                    resp = cloudflare_request(
                        "DELETE", f"{base_url}/{rec['id']}", headers, timeout=30
                    )
                    resp.raise_for_status()
                    if not resp.json().get("success"):
                        raise RuntimeError(resp.json().get("errors"))
                    logger.warning(f"Cloudflare: removed {name} → {ip}")
                    removed += 1
                except requests.exceptions.RequestException as e:
                    logger.error(f"Cloudflare: failed to remove {name} → {ip}: {e}")
                    errors += 1

    if dry_run and not added and not removed and not errors:
        logger.warning("Cloudflare: already in sync, nothing to do")

    logger.info(
        f"Cloudflare sync complete: {added} added, {removed} removed, {errors} errors"
    )
    return errors

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Sync DNS records from UniFi OS to Pi-hole and Cloudflare'
    )
    parser.add_argument(
        '--domain',
        default=None,
        help='Domain suffix for DNS records (e.g., home.example.com). Also settable via SYNC_DOMAIN in .env'
    )
    parser.add_argument(
        '--log-level',
        choices=['error', 'warning', 'info', 'trace'],
        default=None,
        help='Logging level. Also settable via SYNC_LOG_LEVEL in .env (default: info)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        default=False,
        help='Show what would be changed without making any modifications'
    )

    args = parser.parse_args()

    dry_run = args.dry_run
    log_level = args.log_level or os.environ.get("SYNC_LOG_LEVEL", "info").lower()
    if dry_run and log_level in ('error', 'warning'):
        log_level = 'info'
    setup_logging(log_level)

    domain = args.domain or os.environ.get("SYNC_DOMAIN")
    if not domain:
        logger.error("Domain must be specified via --domain or SYNC_DOMAIN in .env")
        return 1

    unifi_ip = os.environ.get("UNIFI_IP")
    unifi_user = os.environ.get("UNIFI_USER", "root")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    pihole_ip = os.environ.get("PIHOLE_IP")
    pihole_password = os.environ.get("PIHOLE_PASSWORD")
    cf_api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
    cf_zone_id = os.environ.get("CLOUDFLARE_ZONE_ID")

    if not all([unifi_ip, unifi_password, pihole_ip, pihole_password]):
        logger.error(
            "UNIFI_IP, UNIFI_PASSWORD, PIHOLE_IP, and PIHOLE_PASSWORD "
            "must be set in .env or environment."
        )
        return 1

    try:
        if dry_run:
            logger.warning("DRY RUN — no changes will be made")
        logger.info(f"Starting sync for domain: {domain}")

        logger.debug("Fetching static DHCP leases from UniFi API...")
        leases = fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password)
        logger.info(f"Found {len(leases)} static leases from UniFi")

        expected = set()
        for lease in leases:
            hostname = lease.get("hostname")
            ip = lease.get("ip")
            if hostname and ip:
                expected.add((f"{hostname}.{domain}", ip))

        logger.info(f"Expected {len(expected)} DNS entries for domain {domain}")

        total_errors = 0

        total_errors += sync_pihole(pihole_ip, pihole_password, domain, expected, dry_run)

        if cf_api_token and cf_zone_id:
            total_errors += sync_cloudflare(cf_api_token, cf_zone_id, domain, expected, dry_run)
        else:
            logger.info(
                "Cloudflare sync skipped "
                "(CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID not configured)"
            )

        return 1 if total_errors > 0 else 0

    except RuntimeError as e:
        if log_level == 'trace':
            logger.exception("Command failed with error:")
        else:
            logger.error(str(e))
        return 1
    except Exception as e:
        if log_level == 'trace':
            logger.exception("Unexpected error occurred:")
        else:
            logger.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
