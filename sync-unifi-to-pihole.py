import os
import json
import re
import requests
import argparse
import logging
import atexit
from contextlib import contextmanager
from requests.packages.urllib3.exceptions import InsecureRequestWarning

try:
    from dotenv import load_dotenv
    # Load environment variables from .env files
    load_dotenv('.env.local')  # Load .env.local first (higher priority)
    load_dotenv('.env')        # Load .env as fallback
except ImportError:
    # dotenv not installed, skip loading .env files
    pass

# Disable SSL warnings for UDM API calls
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
logger = logging.getLogger(__name__)

# Global session tracking for cleanup
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

    # Configure logging format similar to syslog
    formatter = logging.Formatter('sync-udm-to-pihole: %(levelname)s: %(message)s')

    # Custom formatter to use lowercase level names
    class LowercaseFormatter(logging.Formatter):
        def format(self, record):
            # Convert levelname to lowercase for syslog-like appearance
            record.levelname = record.levelname.lower()
            return super().format(record)

    formatter = LowercaseFormatter('sync-udm-to-pihole: %(levelname)s: %(message)s')

    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Configure logger
    logger.setLevel(level)
    logger.addHandler(console_handler)

    # Also configure root logger to suppress noise from other modules
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

    # Convert to lowercase
    hostname = hostname.lower()

    # Replace any non-alphanumeric characters (except hyphens) with hyphens
    hostname = re.sub(r'[^a-z0-9-]', '-', hostname)

    # Remove consecutive hyphens
    hostname = re.sub(r'-+', '-', hostname)

    # Remove leading and trailing hyphens
    hostname = hostname.strip('-')

    # Truncate to 63 characters (RFC limit for a single label)
    hostname = hostname[:63]

    # Ensure it doesn't end with a hyphen after truncation
    hostname = hostname.rstrip('-')

    # Ensure hostname is not empty and doesn't start with a digit (optional, some systems require this)
    if not hostname or hostname[0].isdigit():
        hostname = f"device-{hostname}" if hostname else "device"

    return hostname

def fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password):
    """Fetch static DHCP leases from UniFi OS using REST API."""
    session = requests.Session()

    # Login to UniFi API
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

        # Fetch static DHCP reservations
        api_url = f"https://{unifi_ip}/proxy/network/api/s/default/rest/user"
        api_response = session.get(api_url, headers=headers, verify=False, timeout=10)
        api_response.raise_for_status()

        data = api_response.json()
        if data.get("meta", {}).get("rc") != "ok":
            raise RuntimeError(f"API returned error: {data}")

        # Filter for users with fixed IP addresses
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

# Register cleanup function to run on script exit
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

        # Track this session for cleanup
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
            # Remove from active sessions list
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

        # Parse existing records into a list of (hostname, ip) tuples
        existing_records = []
        for host_entry in hosts:
            # Format: "192.168.0.19 dns1.menalto.com"
            parts = host_entry.strip().split()
            if len(parts) >= 2:
                ip, hostname = parts[0], parts[1]
                existing_records.append((hostname, ip))

        return existing_records

    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to get existing DNS records from Pi-hole: {e}")

def sync(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password, domain):
    """Sync Pi-hole DNS records with UniFi fixed leases for the specified domain."""
    logger.info(f"Starting sync for domain: {domain}")
    
    # Fetch UniFi leases
    logger.debug("Fetching static DHCP leases from UniFi API...")
    leases = fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password)
    logger.info(f"Found {len(leases)} static leases from UniFi")

    # Build expected set from UniFi leases
    expected = set()
    for lease in leases:
        hostname = lease.get("hostname")
        ip = lease.get("ip")
        if not hostname or not ip:
            continue
        fqdn = f"{hostname}.{domain}"
        expected.add((fqdn, ip))

    logger.info(f"Expected {len(expected)} DNS entries for domain {domain}")

    with pihole_session(pihole_ip, pihole_password) as sid:
        # Get existing Pi-hole records
        existing_all = get_existing_pihole_dns_records(pihole_ip, sid)
        
        # Filter to only records for our domain
        existing = set()
        for hostname, ip in existing_all:
            if hostname.endswith(f".{domain}"):
                existing.add((hostname, ip))

        logger.info(f"Found {len(existing)} existing DNS records for domain {domain}")

        # Calculate deltas
        to_add = expected - existing
        to_remove = existing - expected

        logger.info(f"Sync plan: {len(to_add)} to add, {len(to_remove)} to remove")

        # Process additions and removals
        headers = {"accept": "application/json", "sid": sid}
        added = removed = errors = 0

        # Add missing entries
        for fqdn, ip in to_add:
            url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{ip}%20{fqdn}"
            try:
                response = requests.put(url, headers=headers, verify=False, timeout=10)
                response.raise_for_status()
                logger.info(f"Added {fqdn} → {ip}")
                added += 1
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to add {fqdn} → {ip}: {e}")
                errors += 1

        # Remove extra entries
        for fqdn, ip in to_remove:
            url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{ip}%20{fqdn}"
            try:
                response = requests.delete(url, headers=headers, verify=False, timeout=10)
                response.raise_for_status()
                logger.warning(f"Removed {fqdn} → {ip}")
                removed += 1
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to remove {fqdn} → {ip}: {e}")
                errors += 1

        logger.info(f"Sync complete: {added} added, {removed} removed, {errors} errors")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Sync DNS records from UniFi OS to Pi-hole')
    parser.add_argument(
        '--domain',
        required=True,
        help='Domain suffix to use for DNS records (e.g., home.example.com)'
    )
    parser.add_argument(
        '--log-level',
        choices=['error', 'warning', 'info', 'trace'],
        default='info',
        help='Set the logging level (default: info)'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)

    # Get environment variables
    unifi_ip = os.environ.get("UNIFI_IP")
    unifi_user = os.environ.get("UNIFI_USER", "root")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    pihole_ip = os.environ.get("PIHOLE_IP")
    pihole_password = os.environ.get("PIHOLE_PASSWORD")

    if not all([unifi_ip, unifi_password, pihole_ip, pihole_password]):
        logger.error("UNIFI_IP, UNIFI_PASSWORD, PIHOLE_IP, and PIHOLE_PASSWORD must be set in the environment.")
        return 1

    # Execute sync
    try:
        sync(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password, args.domain)
        return 0
    except RuntimeError as e:
        # Show clean error message without stack trace unless trace logging is enabled
        if args.log_level.lower() == 'trace':
            logger.exception("Command failed with error:")
        else:
            logger.error(str(e))
        return 1
    except Exception as e:
        # For unexpected errors, always show stack trace in trace mode, otherwise show generic message
        if args.log_level.lower() == 'trace':
            logger.exception("Unexpected error occurred:")
        else:
            logger.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())