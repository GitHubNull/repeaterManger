# Detailed Usage Tutorial

This document provides detailed instructions for all features of Enhanced Repeater Manager.

---

## Table of Contents

- [1. Installation and Uninstallation](#1-installation-and-uninstallation)
- [2. Interface Overview](#2-interface-overview)
- [3. Request Management](#3-request-management)
- [4. Request Editing and Replay](#4-request-editing-and-replay)
- [5. History Tracking](#5-history-tracking)
- [6. Configuration Panel](#6-configuration-panel)
- [7. Data Import/Export](#7-data-importexport)
- [8. Logging System](#8-logging-system)
- [9. Storage and Data Management](#9-storage-and-data-management)
- [10. Advanced Tips](#10-advanced-tips)
- [11. FAQ](#11-faq)

---

## 1. Installation and Uninstallation

### 1.1 Installation

1. Download the latest JAR file from the GitHub [Releases](../../releases) page
2. Open Burp Suite Professional
3. Navigate to `Extender` → `Extensions` tab
4. Click the `Add` button
5. Select the downloaded JAR file in `Extension file`
6. Click `Next` to complete installation
7. You'll see **"增强型Repeater 插件加载成功"** in the Burp Suite output panel, confirming successful installation

### 1.2 Uninstallation

Select the plugin in `Extender` → `Extensions` and click `Remove`. Saved data will not be deleted.

### 1.3 Updating

Unload the old version and reload the new JAR file. It's recommended to export a data backup before updating.

---

## 2. Interface Overview

After loading, a **"增强型Repeater"** tab appears at the top of Burp Suite, containing three sub-tabs:

### 2.1 Request Management Tab

The main working interface, with the following layout:

```
+---------------------------+-----------------------------------+
|                           |  [New Request] [Clear] Layout: [v]|
|   Request List            |                                   |
|   (search/filter/color/   |   Request Editor | Response Viewer|
|    comments)               |                                   |
+---------------------------+                                   |
|                           +-----------------------------------+
|   History Panel           |   Status Bar: Size / Time / Status |
|   (double-click to load)  |                                   |
+---------------------------+-----------------------------------+
```

- **Top-left**: Request list panel, showing all received/created requests
- **Bottom-left**: History panel, showing replay history for the selected request
- **Right**: Request editor and response viewer with layout switching
- **Bottom**: Status bar showing request/response basic information

### 2.2 Configuration Tab

Contains four sub-tabs:

- **Storage Config**: Database path, storage mode, auto-save parameters
- **Logging**: Log level, file logging, UI logging, Burp console logging
- **Proxy Debugging**: HTTP proxy configuration
- **Data Import/Export**: ERM archive / Postman Collection import/export

### 2.3 Log Tab

Displays plugin runtime logs with level filtering support.

---

## 3. Request Management

### 3.1 Sending Requests to the Plugin

Right-click on any HTTP request in Burp Suite and select **"Send to Enhanced Repeater"** (发送到增强型Repeater). Supported locations include:

- Proxy → HTTP History
- Proxy → Intercept
- Intruder
- Scanner
- Repeater (native)
- Spider

### 3.2 Creating a New Blank Request

Click the **"New Request"** (新建请求) button at the top-right to create a default GET request template:

```
GET / HTTP/1.1
Host: example.com

```

### 3.3 Request List Operations

- **Select request**: Click a request in the list to load its content and history on the right
- **Color marking**: Right-click a list entry to choose a color for categorization (e.g., red=high risk, green=normal)
- **Add comments**: Add text descriptions to requests for later reference
- **Search and filter**: Enter keywords in the search box to quickly locate requests
- **Column display control**: Customize which table columns are shown/hidden

---

## 4. Request Editing and Replay

### 4.1 Editing Requests

The request editor in the top-right area provides a syntax-highlighted text editor for direct editing of:

- Request line (method, path, protocol version)
- Request headers
- Request body

### 4.2 Sending Requests

After editing, click the **"Send"** button to send the request through Burp Suite.

- Requests are sent in background threads, preventing UI freezes
- Cursor changes to wait state during sending
- Bottom status bar shows real-time request progress

### 4.3 Viewing Responses

Response content is displayed in the response viewer on the right:

- Syntax-highlighted HTTP response display
- Status code, response length, and response time shown in the status bar
- Supports HTTP/HTTPS requests with automatic protocol preservation

### 4.4 Layout Switching

The dropdown menu at the top-right offers four layout modes:

| Layout | Description |
|--------|-------------|
| Horizontal | Request on left, response on right (default) |
| Vertical | Request on top, response on bottom |
| Request Only | Only shows the request editor |
| Response Only | Only shows the response viewer |

### 4.5 Clearing Content

Click the **"Clear"** (清空) button to clear the current request and response content.

---

## 5. History Tracking

### 5.1 Automatic Recording

Every request sent is automatically recorded in the history panel, whether successful or failed:

- **Success records**: Contain complete request and response data
- **Failure records**: Marked as "request failed" with error information included

### 5.2 Viewing History

- The bottom-left panel shows all history records for the currently selected request
- Records are sorted in reverse chronological order (newest first)
- Each record displays: status code, response length, response time, timestamp

### 5.3 Replaying History

Double-click any history entry to load that replay's:

- Original request data (loaded into the request editor)
- Response data (loaded into the response viewer)
- Status information (updated in the status bar)

### 5.4 Data Persistence

All history records are automatically saved to the SQLite database and survive Burp Suite restarts.

---

## 6. Configuration Panel

### 6.1 Storage Configuration

| Setting | Description |
|---------|-------------|
| Storage Mode | Auto (default) / Specified Directory / Specified File |
| Current Session | Displays current session directory path (read-only) |
| Storage Directory | Displays base storage directory |
| Session Filename | Specify database filename (only available in specified file mode) |
| Auto-save | Enable/disable automatic saving |
| Save Interval | 1 min / 5 min / 10 min / 30 min / 60 min |

**Storage Mode Details**:

- **Auto mode**: Automatically creates timestamp-named session directory under `~/.burp/`
- **Specified Directory**: Creates timestamp-named session directory under the specified directory
- **Specified File**: Uses the specified database file path directly

### 6.2 Logging Configuration

| Setting | Description |
|---------|-------------|
| Log Level | DEBUG / INFO / WARN / ERROR |
| File Logging | Enable/disable file log output |
| Log Directory | File log save path |
| Max File Size | 1 MB / 5 MB / 10 MB / 50 MB |
| Max Backups | 3 / 5 / 10 / 20 |
| UI Logging | Enable/disable UI panel logging |
| Max Entries | 128 / 256 / 512 / 1024 |
| Burp Console | Enable/disable Burp console output |

### 6.3 Proxy Debugging

| Setting | Description |
|---------|-------------|
| HTTP Proxy | Enable/disable proxy (for debugging) |
| Proxy Host | Proxy server address |
| Proxy Port | Proxy server port |

> The proxy configuration affects all HTTP requests sent by the plugin, useful for debugging through Burp Proxy or other proxy tools.

---

## 7. Data Import/Export

### 7.1 ERM Archive Format

ERM (Enhanced Repeater Manager) is the plugin's native archive format, containing the complete database and body data.

**Export**:
1. Navigate to Configuration → Data Import/Export
2. Click the **"Export"** button in the ERM Archive row
3. Choose whether to encrypt (check the "Encrypt" checkbox)
4. If encrypting, enter a password (AES-256-CBC encryption + HMAC-SHA256 integrity verification)
5. Select the save path to complete export

**Import**:
1. Click the **"Import"** button in the ERM Archive row
2. Select the .erm file
3. If the file is encrypted, enter the password
4. Data is automatically loaded after import completes

### 7.2 Postman Collection

Supports import/export in Postman Collection v2.1 format.

**Export**:
1. Click the **"Export"** button in the Postman row
2. Select the save path to generate a .json file
3. Can be directly imported and used in Postman

**Import**:
1. Click the **"Import"** button in the Postman row
2. Select a Postman Collection v2.1 format .json file
3. Requests are automatically loaded into the list after import

### 7.3 Smart Import

Click the **"Smart Import (Auto-detect Format)"** button, and the plugin will automatically detect the file format:

- `.erm` file → ERM archive import
- `.json` file → Postman Collection import
- Other formats → Unsupported format notification

---

## 8. Logging System

### 8.1 Log Levels

| Level | Prefix | Description |
|-------|--------|-------------|
| DEBUG | [D] | Debug information, only used during development |
| INFO | [*] | General operation information |
| SUCCESS | [+] | Operation success information |
| WARN | [!] | Warning information |
| ERROR | [!] | Error information |

### 8.2 Log Channels

- **Burp Console**: Output to Burp Suite's output panel
- **File Log**: Written to log files in the session directory, with rolling backup support
- **UI Panel**: Displayed in the plugin's log tab

### 8.3 Log Files

Log files are stored in the `logs/` subdirectory of the session directory, supporting:

- Size-based rolling: Automatically creates new files when the size limit is reached
- Backup rotation: Retains a specified number of historical log files
- Configurable single file size and maximum backup count

---

## 9. Storage and Data Management

### 9.1 Session Directory Structure

```
~/.burp/
└── session_20240101_120000/
    ├── repeater_manager.sqlite3   # SQLite database
    ├── blobs/                     # External body data
    │   ├── req_body_abc123.bin    # Request body file
    │   └── resp_body_def456.bin   # Response body file
    └── logs/                      # Log files
        ├── repeater_0.log         # Current log
        ├── repeater_1.log         # Backup log
        └── ...
```

### 9.2 Pool Deduplication Mechanism

The database uses a Pool architecture for content deduplication, reducing storage space usage:

- **string_pool**: Stores domain names, paths, query parameters, etc., deduplicated by hash
- **header_pool**: Stores HTTP header data, identical headers stored only once
- **body_pool**: Stores small body data (inline storage in the database)
- **file_pool**: Stores large body data (external file storage in the blobs/ directory)

### 9.3 Garbage Collection

- Background GC service automatically cleans up zero-reference Pool data
- Runs every 10 minutes by default
- Deleting requests reduces the reference count of associated Pool data
- When reference count reaches zero, data enters the GC queue for cleanup
- Supports full ref_count recalculation and immediate GC triggering

### 9.4 Auto-save

- Enabled by default, runs every 5 minutes
- Performs database checkpoint operations to ensure data is written to the main database file
- Save interval can be adjusted or disabled in the configuration panel

---

## 10. Advanced Tips

### 10.1 HTTPS Request Handling

The plugin automatically preserves HTTPS protocol information:

- Requests sent from the context menu retain original protocol information
- HTTPS protocol is not lost when resending saved requests
- Supports port number recognition in the Host header (e.g., :443 → HTTPS)

### 10.2 Request Timeout Settings

The request editor provides timeout configuration for customizing request timeout duration.

### 10.3 Cross-session Data Migration

Use the ERM archive format for cross-session data migration:

1. Export ERM archive from the old session
2. Switch sessions or restart Burp Suite
3. Import ERM archive in the new session

### 10.4 Team Collaboration

- Export ERM archives (with optional encryption) to share with team members
- Export Postman Collections for sharing with team members who don't use Burp
- Encrypted archives use AES-256-CBC to ensure secure data transfer

---

## 11. FAQ

### Q: I can't see the "增强型Repeater" tab after loading the plugin?

A: Check if the plugin loaded successfully in the Extender → Extensions list, and review any error output. Ensure you're using Burp Suite Professional.

### Q: Is data preserved after restarting Burp Suite?

A: Yes. All requests and history records are saved in the SQLite database and automatically loaded on restart.

### Q: Where are the database files located?

A: By default, in session subdirectories under `~/.burp/`. You can view the current session path in the configuration panel.

### Q: How to reduce disk usage?

A: 1) Delete unneeded requests, and GC will automatically clean up associated data; 2) Export using ERM archives and then clean up old sessions.

### Q: Is ERM encryption secure?

A: ERM encryption uses AES-256-CBC + HMAC-SHA256, with keys derived from passwords via PBKDF2. Please use strong passwords and keep them safe.

### Q: Which Burp Suite versions are supported?

A: Only Burp Suite Professional is supported. The Community edition does not support extension loading.

### Q: Do plugin requests go through Burp's proxy?

A: By default, requests are sent directly without going through Burp's proxy. For debugging, enable HTTP proxy in the configuration panel and point it to Burp Proxy (e.g., 127.0.0.1:8080).
