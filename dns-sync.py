import os
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for UDM API calls
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def fetch_dhcp_leases_from_udm(udm_ip, udm_user, udm_password):
    """Fetch static DHCP leases from UDM using REST API."""
    session = requests.Session()
    
    # Login to UDM API
    login_url = f"https://{udm_ip}/api/auth/login"
    login_data = {
        "username": udm_user,
        "password": udm_password
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
        api_url = f"https://{udm_ip}/proxy/network/api/s/default/rest/user"
        api_response = session.get(api_url, headers=headers, verify=False, timeout=10)
        api_response.raise_for_status()
        
        data = api_response.json()
        if data.get("meta", {}).get("rc") != "ok":
            raise RuntimeError(f"API returned error: {data}")
        
        # Filter for users with fixed IP addresses
        leases = []
        for user in data.get("data", []):
            if user.get("use_fixedip", False) and user.get("fixed_ip"):
                lease = {
                    "ip": user.get("fixed_ip"),
                    "hostname": user.get("hostname") or user.get("name"),
                    "mac": user.get("mac")
                }
                if lease["ip"] and lease["hostname"]:
                    leases.append(lease)
        
        return leases
        
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to fetch config from UDM API: {e}")

def push_dns_records_to_pihole(pihole_url, pihole_token, leases):
    """Push local DNS records to Pi-hole using its API."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for lease in leases:
        ip = lease.get("ip")
        hostname = lease.get("hostname")
        if not ip or not hostname:
            continue

        fqdn = f"{hostname}.noe.menalto.com"
        payload = {
            "action": "add",
            "ip": ip,
            "domain": fqdn,
            "token": pihole_token
        }

        resp = requests.post(f"{pihole_url}/admin/api.php", headers=headers, data=payload)
        if resp.status_code != 200:
            print(f"Failed to add {fqdn} → {ip}: {resp.text}")
        else:
            print(f"Added {fqdn} → {ip}")

def main():
    udm_ip = os.environ.get("UDM_IP")
    udm_user = os.environ.get("UDM_USER", "root")
    udm_password = os.environ.get("UDM_PASSWORD")
    pihole_url = os.environ.get("PIHOLE_URL", "http://192.168.0.19")
    pihole_token = os.environ.get("PIHOLE_TOKEN")

    if not all([udm_ip, udm_password, pihole_token]):
        raise EnvironmentError("UDM_IP, UDM_PASSWORD, and PIHOLE_TOKEN must be set in the environment.")

    print("Fetching static DHCP leases from UDM API...")
    leases = fetch_dhcp_leases_from_udm(udm_ip, udm_user, udm_password)
    print(f"Found {len(leases)} static leases.")

    print("Pushing local DNS records to Pi-hole...")
    push_dns_records_to_pihole(pihole_url, pihole_token, leases)

if __name__ == "__main__":
    main()