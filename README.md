# Sync UniFi to Pi-hole and Cloudflare

A Python script that synchronizes static DHCP lease hostnames from UniFi OS devices to Pi-hole local DNS records and (optionally) Cloudflare DNS. Devices with static IP addresses configured in your UniFi controller become automatically resolvable by hostname through Pi-hole and publicly via Cloudflare.

**Compatible with all UniFi OS devices:**
- UniFi Dream Machine (UDM)
- UniFi Dream Machine Pro (UDM Pro)
- UniFi Dream Machine SE (UDM SE)
- UniFi Cloud Gateway Ultra
- UniFi Cloud Gateway Max
- Any device running UniFi OS

## Features

- **Pi-hole DNS Sync**: Keeps Pi-hole local DNS in sync with UniFi static DHCP leases
- **Cloudflare DNS Sync** (optional): Publishes the same records to Cloudflare, with safe ownership tracking
- **Dry Run Mode**: Preview all changes before applying them with `--dry-run`
- **Automatic Hostname Normalization**: Converts device names to RFC 1123 compliant hostnames
- **Full Synchronization**: Automatically adds missing entries and removes orphaned entries
- **Multiple IP Support**: Handles devices with multiple fixed IPs (e.g. dual-homed hosts)
- **Session Management**: Proper authentication and cleanup for UniFi and Pi-hole APIs
- **Comprehensive Logging**: Configurable logging levels (error, warning, info, trace)

## Prerequisites

- **UniFi OS Device** (UDM, UDM Pro, UDM SE, Cloud Gateway, etc.) with API access
- **Pi-hole v6.0+** with web interface password set
- **Python 3.6+**
- Network connectivity between the machine running this script and both UniFi controller and Pi-hole
- (Optional) **Cloudflare account** with a DNS zone and an API token

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bharat/sync-unifi-to-pihole.git
   cd sync-unifi-to-pihole
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### 1. UniFi Setup

#### Option A: Create a Dedicated User (Recommended)
1. **Access UniFi Web Interface**: Navigate to `https://your-unifi-ip`
2. **Go to Settings → Admins**
3. **Add New Admin**:
   - **Name**: `dns-sync` (or any preferred username)
   - **Role**: `Limited Admin` or `Read Only` (minimum required permissions)
   - **Password**: Create a strong password
   - **Enable Local Access**: Yes

#### Option B: Use Root Account (Less Secure)
You can use the root account, but creating a dedicated user is more secure.

#### Required UniFi Permissions
The user needs access to:
- Network settings (to read DHCP reservations)
- API endpoint: `/proxy/network/api/s/default/rest/user`

### 2. Pi-hole Setup

#### Enable Web Interface Authentication
1. **Access Pi-hole Admin Interface**: Navigate to `http://your-pihole-ip/admin`
2. **Set Admin Password** (if not already set):
   ```bash
   sudo pihole -a -p
   ```

#### Verify API Access
- The script uses Pi-hole's v6.0+ API endpoints
- Ensure your Pi-hole version is 6.0 or newer
- Test API access: `https://your-pihole-ip/api/auth` should be accessible

### 3. Cloudflare Setup (Optional)

Cloudflare sync is opt-in. If you don't configure it, the script syncs to Pi-hole only.

1. **Get your Zone ID**: Go to the [Cloudflare dashboard](https://dash.cloudflare.com), select your domain, and copy the **Zone ID** from the right sidebar of the Overview page.

2. **Create an API Token**: Go to [API Tokens](https://dash.cloudflare.com/profile/api-tokens) and create a token with:
   - **Permissions**: Zone → DNS → Edit
   - **Zone Resources**: Include → Specific zone → *your domain*

3. **Add to `.env`**:
   ```bash
   CLOUDFLARE_API_TOKEN=your_api_token_here
   CLOUDFLARE_ZONE_ID=your_zone_id_here
   ```

#### How Cloudflare record ownership works

The script tags every DNS record it creates with a `comment` field set to `managed-by:sync-unifi-to-pihole`. This ensures:

- **Only records created by this script are ever modified or deleted.** Manually-created records are never touched.
- If a record already exists with the correct name and IP but wasn't created by the script, it is left alone.
- If a managed record's IP changes in UniFi, the old record is removed and a new one is created.
- Hosts with multiple IPs (e.g. dual-homed devices) get separate A records.

### 4. Environment Configuration

Create environment file(s) for your credentials:

#### Option A: Single Environment File
```bash
cp env.example .env
```

Edit `.env`:
```bash
# Sync Settings
SYNC_DOMAIN=home.example.com
SYNC_LOG_LEVEL=warning

# UniFi OS Configuration
UNIFI_IP=192.168.1.1
UNIFI_USER=dns-sync
UNIFI_PASSWORD=your_unifi_password_here

# Pi-hole Configuration
PIHOLE_IP=192.168.1.100
PIHOLE_PASSWORD=your_pihole_admin_password_here

# Cloudflare Configuration (optional)
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here
CLOUDFLARE_ZONE_ID=your_zone_id_here
```

#### Option B: Separate Environment Files
- `.env.local` - Local/development settings (higher priority)
- `.env` - Default/production settings (fallback)

The script loads `.env.local` first, then falls back to `.env` for any missing variables.

#### Option C: System Environment Variables
You can set these as system environment variables instead of using `.env` files. Note that `SYNC_DOMAIN` and `SYNC_LOG_LEVEL` use a `SYNC_` prefix to avoid collisions with common shell variables.

### 5. Network Configuration

Ensure network connectivity:
- **UniFi API**: HTTPS access to `https://UNIFI_IP/api/auth/login`
- **Pi-hole API**: HTTPS access to `https://PIHOLE_IP/api/auth`
- **Cloudflare API** (if enabled): HTTPS access to `https://api.cloudflare.com`
- **Firewall**: Allow outbound HTTPS (443) traffic from the machine running this script

## Usage

### Basic Command

With `SYNC_DOMAIN` set in `.env`:
```bash
python sync-unifi-to-pihole.py
```

Or specify the domain on the command line (overrides `.env`):
```bash
python sync-unifi-to-pihole.py --domain home.example.com
```

### Dry Run

Preview what the script would do without making any changes:
```bash
python sync-unifi-to-pihole.py --dry-run
```

This fetches records from UniFi, Pi-hole, and Cloudflare, computes the diff, and logs every planned add/remove as a `would add` / `would remove` message.

### Logging Levels

Set via `SYNC_LOG_LEVEL` in `.env` or `--log-level` on the command line:

```bash
# Errors only
python sync-unifi-to-pihole.py --log-level error

# Warnings and errors (good for cron -- shows removals)
python sync-unifi-to-pihole.py --log-level warning

# Informational (default -- shows adds and summary counts)
python sync-unifi-to-pihole.py --log-level info

# Debug/trace (shows all API calls and skipped records)
python sync-unifi-to-pihole.py --log-level trace
```

### Help
```bash
python sync-unifi-to-pihole.py --help
```

## How It Works

### Sync Process
1. **Fetch UniFi Leases**: Authenticates with UniFi and retrieves all users with fixed IP addresses
2. **Normalize Hostnames**: Converts device names to RFC 1123 compliant hostnames
3. **Build Expected Set**: Creates `(hostname.domain, ip)` pairs from the leases
4. **Sync to Pi-hole**: Compares expected set against existing Pi-hole DNS records for the domain, adds missing entries, removes orphaned entries
5. **Sync to Cloudflare** (if configured): Compares expected set against Cloudflare A records under the domain, creates missing records (tagged with ownership comment), deletes managed records no longer in UniFi
6. **Session Cleanup**: Logs out of UniFi and Pi-hole APIs

### Hostname Normalization
The script automatically normalizes device hostnames to ensure DNS compatibility:
- Converts to lowercase
- Replaces invalid characters with hyphens
- Removes consecutive hyphens
- Ensures hostnames don't start/end with hyphens
- Truncates to 63 characters (RFC limit)
- Prefixes with "device-" if hostname starts with a digit

Example transformations:
- `"John's iPhone"` → `"johns-iphone.your-domain.com"`
- `"WiFi_Printer_2024"` → `"wifi-printer-2024.your-domain.com"`
- `"192-test"` → `"device-192-test.your-domain.com"`

## Automation

### Cron Job Example
Run sync every 10 minutes:
```bash
# Add to crontab (crontab -e)
*/10 * * * * cd /path/to/sync-unifi-to-pihole && .venv/bin/python3 sync-unifi-to-pihole.py
```

With `SYNC_DOMAIN` and `SYNC_LOG_LEVEL` set in `.env`, no command line arguments are needed.

### Systemd Timer Example
Create `/etc/systemd/system/sync-unifi-to-pihole.service`:
```ini
[Unit]
Description=Sync UniFi DHCP leases to Pi-hole and Cloudflare DNS
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/path/to/sync-unifi-to-pihole
ExecStart=/path/to/sync-unifi-to-pihole/.venv/bin/python3 sync-unifi-to-pihole.py
```

Create `/etc/systemd/system/sync-unifi-to-pihole.timer`:
```ini
[Unit]
Description=Run UniFi to Pi-hole/Cloudflare sync every 10 minutes
Requires=sync-unifi-to-pihole.service

[Timer]
OnCalendar=*:0/10
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl enable sync-unifi-to-pihole.timer
sudo systemctl start sync-unifi-to-pihole.timer
```

## Troubleshooting

### Common Issues

#### Authentication Failures
```
Pi-hole authentication failed: incorrect password
```
- **Solution**: Verify Pi-hole admin password is correct in `.env`
- **Check**: Ensure Pi-hole web interface password is set (`sudo pihole -a -p`)

#### UniFi API Access Denied
```
UniFi authentication failed: incorrect username or password
```
- **Solution**: Verify UniFi credentials and user permissions
- **Check**: Ensure UniFi user has network access permissions

#### Cloudflare Authentication Failed
```
Cloudflare authentication failed. Check your CLOUDFLARE_API_TOKEN.
```
- **Solution**: Ensure you're using an **API Token** (not a Global API Key). Create one at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with Zone → DNS → Edit permission.

#### Network Connectivity Issues
```
Failed to authenticate with UniFi: Connection timeout
```
- **Solution**: Verify IP addresses and network connectivity
- **Check**: Test manual access to `https://UNIFI_IP` and `https://PIHOLE_IP/admin`

#### SSL Certificate Warnings
The script disables SSL warnings for UniFi and Pi-hole connections (common with self-signed certificates). This is normal behavior.

### Debug Mode
Enable detailed logging for troubleshooting:
```bash
python sync-unifi-to-pihole.py --log-level trace
```

### Manual API Testing

#### Test UniFi API Access
```bash
curl -k -X POST "https://UNIFI_IP/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"your_user","password":"your_password"}'
```

#### Test Pi-hole API Access
```bash
curl -k -X POST "https://PIHOLE_IP/api/auth" \
  -H "Content-Type: application/json" \
  -d '{"password":"your_pihole_password"}'
```

#### Test Cloudflare API Access
```bash
curl "https://api.cloudflare.com/client/v4/zones/YOUR_ZONE_ID/dns_records?type=A&per_page=10" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

## Security Considerations

1. **Secure Credentials**: Use environment files (`.env`) and never commit passwords to version control
2. **Limited UniFi User**: Create a dedicated read-only UniFi user instead of using root
3. **Scoped Cloudflare Token**: Create a token with minimal permissions (DNS Edit on a single zone)
4. **Network Security**: Run on a trusted network segment with proper firewall rules
5. **File Permissions**: Restrict access to `.env` files (`chmod 600 .env`)
6. **Regular Updates**: Keep Pi-hole and UniFi firmware updated

## Dependencies

- **python-dotenv**: Environment variable management from `.env` files
- **requests**: HTTP library for API calls

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for the full license text.

This license ensures that the software remains free and open source, and that any derivative works are also distributed under the same license terms.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: General questions and community support via GitHub Discussions
