# Quick Start Guide

> Get started with Repeater Manager in 5 minutes

## 1. Install the Plugin

1. Download the latest JAR file from [Releases](../../releases)
2. Open Burp Suite Professional
3. Navigate to `Extensions` → `Installed` → Click `Add`
4. Select the downloaded JAR file → Click `Next`
5. You'll see **"Repeater Manager 插件加载成功"** confirming successful installation

> On first load, a session directory is automatically created under `~/.burp/` with database files and logs.

## 2. Send a Request

Right-click on any HTTP request in Burp Suite:

- Select **"Send to Repeater Manager"** (发送到 Repeater Manager)
- Switch to the **"Repeater Manager"** tab at the top

## 3. Edit and Replay

- Top-right area: Edit request content (with syntax highlighting)
- Click the **"Send"** button to replay the request
- Right panel displays the response content
- Bottom status bar shows response time and size

## 4. View History

- Bottom-left panel: View all historical replay records for the request
- Double-click a history entry: Load that replay's request and response
- Use Advanced Search (multi-condition filtering) to quickly find entries
- Right-click menu supports column control, color marking, etc.

## 5. Manage Requests

- **Color marking**: Right-click a request in the list to choose a color
- **Comments**: Add annotation notes to requests
- **Search**: Enter keywords in the search box to quickly locate requests
- **New request**: Click the toolbar button at the top
- **Column control**: Customize which columns to display

## 6. API Rule Extraction

- Navigate to **"Configuration"** → **"API Rule Config"** tab
- Add global rules (cross-session shared, YAML storage) or project rules (SQLite storage)
- Configure extraction source (URL path/query/header/body) and method (regex/substring/JSONPath/XPath)
- Right-click to trigger extraction, or auto re-extract when rules change
- View and manage extraction results in the request list

## 7. Privilege Testing

- Navigate to the **"Configuration"** panel and configure:
  - **User Sessions**: Add users with different privileges (credentials/tokens and token locations)
  - **Judgment Rules**: Set conditions for detecting privilege escalation (status code/response body/header/time)
  - **Request Scope**: Specify URL patterns to test
- Enable auto-testing; the plugin intercepts scope-matched proxy traffic
- Auto-replaces tokens and replays requests, judges risk based on rules
- View results in the Privilege Test panel (color coded: red = potential escalation, green = safe)

## 8. Export Data

Navigate to **"Configuration"** → **"Data Import/Export"**:

- **ERM Archive**: Export/import in plugin-specific format, with optional AES-256 encryption
- **Postman**: Export as Postman Collection v2.1 format
- **Smart Import**: Automatically detect file format

---

> For more features, refer to the [Detailed Usage Tutorial](usage_detailed_en.md)
