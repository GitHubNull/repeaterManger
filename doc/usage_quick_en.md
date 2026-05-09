# Quick Start Guide

> Get started with Repeater Manager in 5 minutes

---

## 1. Install the Plugin

1. Download the latest JAR file from [Releases](../../releases)
2. Open Burp Suite Professional
3. Navigate to `Extensions` → `Installed` → Click `Add`
4. Select the downloaded JAR file → Click `Next`
5. You'll see **"Repeater Manager 插件加载成功"** confirming successful installation

> On first load, a session directory is automatically created under `~/.burp/` with database files and logs.

---

## 2. Send a Request to the Plugin

Right-click on any HTTP request in Burp Suite (Proxy/Intruder/Scanner, etc.):

- Select **"Send to Repeater Manager"**
- Switch to the **"Repeater Manager"** tab at the top to see the request added to the list

---

## 3. Edit and Replay

- **Top-right area**: Edit request content (with syntax highlighting)
- Click the **"Send"** button to replay the request
- **Bottom-right / Right side**: Displays the response content
- **Bottom status bar**: Shows response time and size

---

## 4. View History

- **Bottom-left panel**: View all historical replay records for the request
- Records are sorted in reverse chronological order, showing status code, response length, and response time
- **Double-click** a history entry: Load that replay's request and response
- Use **Advanced Search** (multi-condition filtering) to quickly find entries

---

## 5. Manage Requests

- **Color marking**: Right-click a request in the list to choose a color for categorization
- **Comments**: Add annotation notes to requests
- **Search**: Enter keywords in the search box to quickly locate requests
- **New request**: Click the **"New Request"** button in the top toolbar
- **Delete request**: Right-click and select delete to clean up unwanted requests

---

## 6. Switch Layout

Click the **"Layout"** dropdown in the top-right corner to choose your preferred display mode:

| Layout | Description |
|--------|-------------|
| Horizontal | Request on left, response on right (default) |
| Vertical | Request on top, response on bottom |
| Request Only | Only shows the request editor |
| Response Only | Only shows the response viewer |

---

## 7. Column Display Control

- Right-click on the request list header to open the **"Column Control"** dialog
- Check/uncheck to show or hide specific columns
- Common columns include: ID, Method, Domain, Path, Status Code, Response Length, Color, Comments, etc.

---

## 8. Configure Storage and Logging

Navigate to the **"Configuration"** tab:

### Storage Configuration
- **Storage Mode**: Auto (default) / Specified Directory / Specified File
- **Auto-save**: Automatically syncs data to disk every 5 minutes by default

### Logging Configuration
- **Log Level**: DEBUG / INFO / SUCCESS / WARN / ERROR
- **Log Channels**: Burp Console / File Log / UI Panel Log
- Log files are saved in the `logs/` subdirectory of the session directory

---

## 9. Import and Export Data

Navigate to **"Configuration"** → **"Data Import/Export"** tab:

- **ERM Archive**: Plugin-specific format with optional AES-256 encryption, suitable for backups and team sharing
- **Postman Collection**: Export as v2.1 format for collaboration with other tools
- **Smart Import**: Automatically detects file format (.erm / .json)

> It is recommended to export an ERM archive as a backup before updating the plugin.

---

## 10. API Rule Extraction

The plugin can automatically extract API paths from non-standard requests for easier organization:

1. Navigate to **"Configuration"** → **"API Rule Config"** tab
2. Add **Global Rules** (cross-session shared, YAML storage) or **Project Rules** (session-independent SQLite storage)
3. Configure extraction source (URL path / query / header / body) and method (regex / substring / JSONPath / XPath)
4. Trigger extraction via right-click menu, or auto re-extract when rules change
5. View and manage extraction results in the request list

---

## 11. Privilege Testing

Automated privilege escalation vulnerability detection:

1. Navigate to the **"Configuration"** panel and configure:
   - **User Sessions**: Add credentials/tokens for users with different privilege levels
   - **Token Location**: Configure where the token is in the request (Header / Cookie / Body / URL Parameter)
   - **Judgment Rules**: Set conditions for detecting privilege escalation (status code / response body / header / response time)
   - **Request Scope**: Specify URL patterns to test
2. Enable auto-testing; the plugin intercepts scope-matched proxy traffic
3. Auto-replaces tokens and replays requests, judges risk based on rules
4. View results in the **"Privilege Test"** panel (color coded: red = potential escalation, green = safe)

---

> For more feature details, refer to the [Detailed Usage Tutorial](usage_detailed_en.md)
