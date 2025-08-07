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
    # Format: sync-udm-to-pihole: level: message (lowercase, no timestamps since this is interactive)
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
        # Note: This endpoint gets configured users/clients which includes static leases
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
            json={"password": pihole_password},  # Send password as JSON object
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
        # This preserves multiple entries with the same hostname
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

def push_dns_records_to_pihole(pihole_ip, pihole_password, leases):
    """Push local DNS records to Pi-hole using v6.0 API."""
    with pihole_session(pihole_ip, pihole_password) as sid:
        # Get existing DNS records to avoid duplicates
        existing_records = get_existing_pihole_dns_records(pihole_ip, sid)
        logger.debug(f"Found {len(existing_records)} existing DNS records in Pi-hole")
        
        # Convert list of tuples to a set of (hostname, ip) pairs for fast lookup
        existing_pairs = set(existing_records)
        
        headers = {
            "accept": "application/json",
            "sid": sid
        }
        
        added_count = 0
        skipped_count = 0
        error_count = 0
        
        # Track hostnames we've seen to detect duplicates
        seen_hostnames = {}
        
        for lease in leases:
            ip = lease.get("ip")
            hostname = lease.get("hostname")
            if not ip or not hostname:
                continue

            fqdn = f"{hostname}.noe.menalto.com"
            
            # Check if exact record already exists (same hostname and IP)
            if (fqdn, ip) in existing_pairs:
                logger.debug(f"Skipped {fqdn} → {ip} (already exists)")
                skipped_count += 1
                continue
                
            # Check if hostname exists with different IP
            existing_ips_for_hostname = [record_ip for record_hostname, record_ip in existing_records if record_hostname == fqdn]
            if existing_ips_for_hostname:
                logger.warning(f"Skipped {fqdn} → {ip} (hostname exists with different IPs: {', '.join(existing_ips_for_hostname)})")
                skipped_count += 1
                continue
                
            # Check for duplicate hostnames in current batch
            if fqdn in seen_hostnames:
                logger.warning(f"Skipped {fqdn} → {ip} (duplicate hostname in batch, keeping first: {seen_hostnames[fqdn]})")
                skipped_count += 1
                continue
            
            seen_hostnames[fqdn] = ip
            
            # Add/update the DNS record using PUT endpoint
            # URL format: /api/config/dns%2Fhosts/{ip}%20{hostname}
            dns_url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{ip}%20{fqdn}"
            
            try:
                response = requests.put(dns_url, headers=headers, verify=False, timeout=10)
                response.raise_for_status()
                
                logger.info(f"Added {fqdn} → {ip}")
                added_count += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to add {fqdn} → {ip}: {e}")
                error_count += 1
        
        logger.info(f"DNS sync complete: {added_count} added, {skipped_count} skipped, {error_count} errors")

def delete_dns_record_from_pihole(pihole_ip, sid, fqdn):
    """Delete a DNS record from Pi-hole v6.0 API."""
    # URL format for deletion: DELETE /api/config/dns%2Fhosts/{entry}
    # where entry is the full "ip hostname" string
    delete_url = f"https://{pihole_ip}/api/config/dns%2Fhosts/{fqdn}"
    headers = {
        "accept": "application/json",
        "sid": sid
    }
    
    try:
        response = requests.delete(delete_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to delete {fqdn}: {e}")
        return False

def test_authentication(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password):
    """Test authentication with both UniFi and Pi-hole before proceeding with operations."""
    logger.info("Testing authentication with UniFi and Pi-hole...")
    
    # Test UniFi authentication
    logger.debug("Testing UniFi authentication...")
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
        logger.debug("UniFi authentication successful")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [401, 403]:
            raise RuntimeError(f"UniFi authentication failed: incorrect username or password for user '{unifi_user}'. Please check your UNIFI_USER and UNIFI_PASSWORD environment variables.")
        else:
            raise RuntimeError(f"Failed to authenticate with UniFi: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to connect to UniFi: {e}")
    
    # Test Pi-hole authentication
    logger.debug("Testing Pi-hole authentication...")
    with pihole_session(pihole_ip, pihole_password) as sid:
        logger.debug("Pi-hole authentication successful")
    
    logger.info("Authentication test completed successfully")

def update_command(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password):
    """Update Pi-hole with entries from UniFi (merge operation)."""
    # Test authentication with both systems first
    test_authentication(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password)
    
    logger.debug("Fetching static DHCP leases from UniFi API...")
    leases = fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password)
    logger.info(f"Found {len(leases)} static leases from UniFi")

    logger.debug("Pushing local DNS records to Pi-hole...")
    push_dns_records_to_pihole(pihole_ip, pihole_password, leases)

def cleanup_command(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password):
    """Find and optionally remove Pi-hole entries that don't exist in UniFi."""
    # Test authentication with both systems first
    test_authentication(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password)
    
    logger.debug("Fetching static DHCP leases from UniFi API...")
    leases = fetch_dhcp_leases_from_unifi(unifi_ip, unifi_user, unifi_password)
    
    # Create a set of FQDNs that should exist (from UniFi)
    unifi_fqdns = set()
    for lease in leases:
        hostname = lease.get("hostname")
        if hostname:
            fqdn = f"{hostname}.noe.menalto.com"
            unifi_fqdns.add(fqdn)
    
    logger.info(f"Found {len(unifi_fqdns)} expected DNS entries from UniFi")
    
    with pihole_session(pihole_ip, pihole_password) as sid:
        # Get existing Pi-hole records
        existing_records = get_existing_pihole_dns_records(pihole_ip, sid)
        
        # Find orphaned entries (in Pi-hole but not in UniFi)
        # existing_records is now a list of (hostname, ip) tuples
        orphaned_records = []
        for hostname, ip in existing_records:
            if hostname.endswith('.noe.menalto.com') and hostname not in unifi_fqdns:
                orphaned_records.append((hostname, ip))
        
        if not orphaned_records:
            logger.info("No orphaned DNS records found in Pi-hole")
            return
        
        logger.info(f"Found {len(orphaned_records)} orphaned DNS records in Pi-hole:")
        for hostname, ip in orphaned_records:
            logger.info(f"  {hostname} → {ip}")
        
        # Ask for confirmation
        print()
        response = input(f"Delete {len(orphaned_records)} orphaned records from Pi-hole? [y/N]: ").strip().lower()
        
        if response not in ['y', 'yes']:
            logger.info("Cleanup cancelled by user")
            return
        
        # Delete the orphaned records
        deleted_count = 0
        failed_count = 0
        
        for hostname, ip in orphaned_records:
            logger.debug(f"Deleting {hostname} → {ip}")
            if delete_dns_record_from_pihole(pihole_ip, sid, f"{ip}%20{hostname}"):
                logger.info(f"Deleted {hostname} → {ip}")
                deleted_count += 1
            else:
                failed_count += 1
        
        logger.info(f"Cleanup complete: {deleted_count} deleted, {failed_count} failed")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Sync DNS records from UniFi OS to Pi-hole')
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update Pi-hole with entries from UniFi')
    update_parser.add_argument(
        '--log-level', 
        choices=['error', 'warning', 'info', 'trace'], 
        default='info',
        help='Set the logging level (default: info)'
    )
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Remove Pi-hole entries not found in UniFi')
    cleanup_parser.add_argument(
        '--log-level', 
        choices=['error', 'warning', 'info', 'trace'], 
        default='info',
        help='Set the logging level (default: info)'
    )
    
    args = parser.parse_args()
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    setup_logging(args.log_level)
    
    unifi_ip = os.environ.get("UNIFI_IP")
    unifi_user = os.environ.get("UNIFI_USER", "root")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    pihole_ip = os.environ.get("PIHOLE_IP")
    pihole_password = os.environ.get("PIHOLE_PASSWORD")

    if not all([unifi_ip, unifi_password, pihole_ip, pihole_password]):
        logger.error("UNIFI_IP, UNIFI_PASSWORD, PIHOLE_IP, and PIHOLE_PASSWORD must be set in the environment.")
        return 1

    # Execute the requested command
    try:
        if args.command == 'update':
            update_command(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password)
        elif args.command == 'cleanup':
            cleanup_command(unifi_ip, unifi_user, unifi_password, pihole_ip, pihole_password)
        
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