# Sync UniFi to Pi-hole

A Python script that synchronizes static DHCP lease hostnames from UniFi OS devices to Pi-hole local DNS records. This ensures that devices with static IP addresses configured in your UniFi controller are automatically resolvable by hostname through Pi-hole.

**Compatible with all UniFi OS devices:**
- UniFi Dream Machine (UDM)
- UniFi Dream Machine Pro (UDM Pro) 
- UniFi Dream Machine SE (UDM SE)
- UniFi Cloud Gateway Ultra
- UniFi Cloud Gateway Max
- Any device running UniFi OS

## Features

- **Automatic Hostname Normalization**: Converts device names to RFC 1123 compliant hostnames
- **Duplicate Detection**: Prevents duplicate DNS entries and conflicts
- **Session Management**: Proper authentication and cleanup for both UniFi and Pi-hole APIs
- **Two Operation Modes**:
  - `update`: Add/merge UniFi static leases into Pi-hole DNS records
  - `cleanup`: Find and optionally remove orphaned Pi-hole DNS entries not found in UniFi
- **Comprehensive Logging**: Configurable logging levels (error, warning, info, trace)
- **Domain Suffix**: Automatically appends `.noe.menalto.com` to hostnames (configurable in code)

## Prerequisites

- **UniFi OS Device** (UDM, UDM Pro, UDM SE, Cloud Gateway, etc.) with API access
- **Pi-hole v6.0+** with web interface password set
- **Python 3.6+**
- Network connectivity between the machine running this script and both UniFi controller and Pi-hole

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bharat/sync-udm-to-pihole.git
   cd sync-udm-to-pihole
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
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
   # On Pi-hole server
   sudo pihole -a -p
   ```
   Enter a strong password when prompted.

#### Verify API Access
- The script uses Pi-hole's v6.0+ API endpoints
- Ensure your Pi-hole version is 6.0 or newer
- Test API access: `https://your-pihole-ip/api/auth` should be accessible

### 3. Environment Configuration

Create environment file(s) for your credentials:

#### Option A: Single Environment File
```bash
cp env.example .env
```

Edit `.env`:
```bash
# UniFi OS Configuration (UDM, UDM Pro, UDM SE, Cloud Gateway, etc.)
UNIFI_IP=192.168.1.1
UNIFI_USER=dns-sync
UNIFI_PASSWORD=your_unifi_password_here

# Pi-hole Configuration  
PIHOLE_IP=192.168.1.100
PIHOLE_PASSWORD=your_pihole_admin_password_here
```

#### Option B: Separate Environment Files (Recommended for multiple environments)
- `.env.local` - Local/development settings (higher priority)
- `.env` - Default/production settings (fallback)

The script loads `.env.local` first, then falls back to `.env` for any missing variables.

#### Option C: System Environment Variables
You can also set these as system environment variables instead of using `.env` files:
```bash
export UNIFI_IP=192.168.1.1
export UNIFI_USER=dns-sync
export UNIFI_PASSWORD=your_unifi_password_here
export PIHOLE_IP=192.168.1.100
export PIHOLE_PASSWORD=your_pihole_admin_password_here
```

### 4. Network Configuration

Ensure network connectivity:
- **UniFi API**: HTTPS access to `https://UNIFI_IP/api/auth/login`
- **Pi-hole API**: HTTPS access to `https://PIHOLE_IP/api/auth`
- **Firewall**: Allow outbound HTTPS (443) traffic from the machine running this script

## Usage

### Basic Commands

#### Update Pi-hole with UniFi Static Leases
```bash
python sync-udm-to-pihole.py update
```

#### Find and Remove Orphaned DNS Records
```bash
python sync-udm-to-pihole.py cleanup
```

### Advanced Options

#### Logging Levels
```bash
# Minimal output (errors only)
python sync-udm-to-pihole.py update --log-level error

# Verbose output (includes debug information)
python sync-udm-to-pihole.py update --log-level trace

# Default informational output
python sync-udm-to-pihole.py update --log-level info
```

#### Help
```bash
python sync-udm-to-pihole.py --help
python sync-udm-to-pihole.py update --help
python sync-udm-to-pihole.py cleanup --help
```

## How It Works

### Update Process
1. **Authenticate with UniFi**: Logs into UniFi API using provided credentials
2. **Fetch Static DHCP Leases**: Retrieves all configured users with fixed IP addresses
3. **Normalize Hostnames**: Converts device names to RFC 1123 compliant hostnames
4. **Authenticate with Pi-hole**: Logs into Pi-hole v6.0 API
5. **Check Existing Records**: Retrieves current Pi-hole DNS records to avoid duplicates
6. **Add New Records**: Creates DNS entries in format: `hostname.noe.menalto.com → IP`
7. **Session Cleanup**: Properly logs out of both APIs

### Cleanup Process
1. **Fetch UniFi Data**: Gets current static DHCP leases from UniFi
2. **Compare with Pi-hole**: Identifies DNS records in Pi-hole that don't exist in UniFi
3. **Interactive Confirmation**: Prompts user before deleting orphaned records
4. **Safe Deletion**: Only removes records matching the configured domain suffix

### Hostname Normalization
The script automatically normalizes device hostnames to ensure DNS compatibility:
- Converts to lowercase
- Replaces invalid characters with hyphens
- Removes consecutive hyphens
- Ensures hostnames don't start/end with hyphens
- Truncates to 63 characters (RFC limit)
- Prefixes with "device-" if hostname starts with a digit

Example transformations:
- `"John's iPhone"` → `"johns-iphone.noe.menalto.com"`
- `"WiFi_Printer_2024"` → `"wifi-printer-2024.noe.menalto.com"`
- `"192-test"` → `"device-192-test.noe.menalto.com"`

## Customization

### Change Domain Suffix
Edit line 295 in `sync-udm-to-pihole.py`:
```python
fqdn = f"{hostname}.your-domain.com"  # Change this line
```

Also update line 372 and 385 for cleanup functionality:
```python
fqdn = f"{hostname}.your-domain.com"  # Line 372
if hostname.endswith('.your-domain.com') and hostname not in udm_fqdns:  # Line 385
```

### Modify Hostname Normalization
Edit the `normalize_hostname()` function (lines 64-99) to customize hostname processing rules.

## Automation

### Cron Job Example
Run sync every hour:
```bash
# Add to crontab (crontab -e)
0 * * * * /path/to/sync-udm-to-pihole/venv/bin/python /path/to/sync-udm-to-pihole/sync-udm-to-pihole.py update --log-level warning
```

### Systemd Timer Example
Create `/etc/systemd/system/udm-pihole-sync.service`:
```ini
[Unit]
Description=Sync UDM to Pi-hole DNS records
After=network.target

[Service]
Type=oneshot
User=your-user
WorkingDirectory=/path/to/sync-udm-to-pihole
Environment=PATH=/path/to/sync-udm-to-pihole/venv/bin
ExecStart=/path/to/sync-udm-to-pihole/venv/bin/python sync-udm-to-pihole.py update --log-level warning
```

Create `/etc/systemd/system/udm-pihole-sync.timer`:
```ini
[Unit]
Description=Run UDM to Pi-hole sync hourly
Requires=udm-pihole-sync.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl enable udm-pihole-sync.timer
sudo systemctl start udm-pihole-sync.timer
```

## Troubleshooting

### Common Issues

#### Authentication Failures
```
Failed to authenticate with Pi-hole: 401 Client Error
```
- **Solution**: Verify Pi-hole admin password is correct
- **Check**: Ensure Pi-hole web interface password is set (`sudo pihole -a -p`)

#### UniFi API Access Denied
```
Failed to fetch config from UniFi API: 403 Forbidden
```
- **Solution**: Verify UniFi credentials and user permissions
- **Check**: Ensure UniFi user has network access permissions

#### Network Connectivity Issues
```
Failed to authenticate with UniFi: Connection timeout
```
- **Solution**: Verify IP addresses and network connectivity
- **Check**: Test manual access to `https://UNIFI_IP` and `https://PIHOLE_IP/admin`

#### SSL Certificate Warnings
The script disables SSL warnings for UniFi connections (common with self-signed certificates). This is normal behavior.

### Debug Mode
Enable detailed logging for troubleshooting:
```bash
python sync-udm-to-pihole.py update --log-level trace
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

## Security Considerations

1. **Secure Credentials**: Use environment files (`.env`) and never commit passwords to version control
2. **Limited UniFi User**: Create a dedicated read-only UniFi user instead of using root
3. **Network Security**: Run on a trusted network segment with proper firewall rules
4. **File Permissions**: Restrict access to `.env` files (`chmod 600 .env`)
5. **Regular Updates**: Keep Pi-hole and UniFi firmware updated

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
