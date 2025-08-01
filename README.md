# Website Security & Blocking Tool

A comprehensive Python tool that allows you to check website security using VirusTotal API and block/unblock malicious websites by modifying the system's hosts file.

## Features

### 🔒 Security Check
- Check website security using VirusTotal API
- Real-time threat detection from multiple antivirus engines
- Detailed security reports with detection rates
- Threaded operations to prevent GUI freezing

### 🚫 Website Blocking
- Block malicious websites by adding entries to hosts file
- Cross-platform support (Windows, Linux, macOS)
- Password-protected admin operations
- Direct integration with security check results

### 🔓 Website Unblocking
- Remove blocked websites from hosts file
- Secure password verification
- Clean removal of blocking entries

### 📋 Management
- View all currently blocked websites
- Refresh blocked sites list
- Easy-to-use tabbed interface

## Installation

1. **Clone or download this repository**
   ```bash
   git clone <repository-url>
   cd Block-malicious-websites-
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Get VirusTotal API Key** (Optional but recommended)
   - Visit [VirusTotal](https://www.virustotal.com/)
   - Create a free account
   - Get your API key from your profile
   - Replace the API key in `website_security_tool.py` (line 25)

## Usage

### Running the Tool

**Windows:**
```bash
python website_security_tool.py
```

**Linux/macOS:**
```bash
python3 website_security_tool.py
```

**Note:** You may need to run as administrator/root to modify the hosts file.

### Default Credentials
- **Admin Password:** `admin123`
- **VirusTotal API Key:** Included in the code (replace with your own for better rate limits)

### How to Use

#### 1. Security Check Tab
1. Enter a website URL (e.g., `https://example.com`)
2. Click "Check Security"
3. View the security report
4. If malicious, click "Block Website" to automatically switch to blocking tab

#### 2. Block Website Tab
1. Enter the website domain to block (e.g., `malicious-site.com`)
2. Enter admin password
3. Click "Block Website"
4. The website will be blocked system-wide

#### 3. Unblock Website Tab
1. Enter the website domain to unblock
2. Enter admin password
3. Click "Unblock Website"
4. The website will be accessible again

#### 4. View Blocked Sites Tab
1. View all currently blocked websites
2. Click "Refresh List" to update the display
3. See total count of blocked sites

## Technical Details

### How It Works

#### Security Checking
- Uses VirusTotal's public API to check website reputation
- Queries multiple antivirus engines simultaneously
- Provides detection rate and detailed threat information
- Runs in background threads to maintain responsive GUI

#### Website Blocking
- Modifies the system's hosts file (`/etc/hosts` on Unix, `C:\Windows\System32\drivers\etc\hosts` on Windows)
- Adds entries like `127.0.0.1 malicious-site.com`
- Redirects blocked domains to localhost (127.0.0.1)
- Works system-wide for all applications

### File Structure
```
├── website_security_tool.py    # Main application
├── requirements.txt            # Python dependencies
├── README.md                  # This file
└── .gitattributes            # Git configuration
```

### Supported Operating Systems
- **Windows:** Windows 10/11
- **Linux:** Ubuntu, Debian, CentOS, etc.
- **macOS:** All recent versions

## Security Considerations

### ⚠️ Important Notes
1. **Run as Administrator:** The tool needs admin privileges to modify the hosts file
2. **API Rate Limits:** VirusTotal has rate limits for free API usage
3. **Password Security:** Change the default password in the code
4. **Backup:** Consider backing up your hosts file before making changes

### Best Practices
- Use your own VirusTotal API key for better rate limits
- Change the default admin password
- Regularly review blocked websites
- Keep the tool updated

## Troubleshooting

### Common Issues

**Permission Denied Error:**
- Run the application as administrator/root
- On Windows: Right-click and "Run as administrator"
- On Linux/macOS: Use `sudo python3 website_security_tool.py`

**VirusTotal API Errors:**
- Check your internet connection
- Verify the API key is correct
- Consider getting your own API key for better limits

**Hosts File Not Found:**
- Ensure you're running on a supported operating system
- Check if the hosts file exists in the expected location

### Error Messages
- **"Permission denied"** → Run as administrator
- **"Unsupported operating system"** → Check OS compatibility
- **"Please Enter a Valid Password"** → Use the correct admin password

## Contributing

Feel free to contribute to this project by:
- Reporting bugs
- Suggesting new features
- Improving the UI/UX
- Adding support for additional security APIs

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for educational and security purposes. Users are responsible for:
- Ensuring they have permission to block websites
- Complying with local laws and regulations
- Using the tool responsibly and ethically

The developers are not responsible for any misuse of this tool.
