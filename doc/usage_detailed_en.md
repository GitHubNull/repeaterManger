# Detailed Usage Tutorial

This document provides detailed instructions for all features of Repeater Manager. It is recommended to read through the chapters in order.

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
- [10. API Rule Extraction](#10-api-rule-extraction)
- [11. Privilege Testing](#11-privilege-testing)
- [12. Message Comparison](#12-message-comparison)
- [13. Batch Operations](#13-batch-operations)
- [14. Report Export](#14-report-export)
- [15. Advanced Tips](#15-advanced-tips)
- [16. FAQ](#16-faq)

---

## 1. Installation and Uninstallation

### 1.1 Prerequisites

- Burp Suite Professional 2024.1 or higher
- Java 17 or higher

### 1.2 Installation Steps

1. Download the latest JAR file from the GitHub [Releases](../../releases) page
2. Open Burp Suite Professional
3. Navigate to `Extensions` → `Installed` tab
4. Click the `Add` button
5. Select the downloaded JAR file in `Extension file`
6. Click `Next` to complete installation
7. You'll see **"Repeater Manager 插件加载成功"** in the Burp Suite output panel, confirming successful installation

> On first load, the plugin automatically creates a session directory (named with a timestamp) under `~/.burp/`, containing the database file, body data directory, and logs directory. Global API extraction rules are stored in `~/.burp/repeater_manager/api_extraction_rules.yaml`.

### 1.3 Uninstallation

Select the plugin in `Extensions` → `Installed` and click `Remove`. Saved data will not be deleted.

### 1.4 Updating

Unload the old version and reload the new JAR file. It's recommended to export an ERM archive as a backup before updating.

---

## 2. Interface Overview

After loading, a **"Repeater Manager"** tab appears at the top of Burp Suite, containing three sub-tabs:

### 2.1 Request Management Tab

The main working interface, with the following layout:

```
+---------------------------+-----------------------------------+
|                           |  [New Request] [Clear] Layout: [v]|
|   Request List            |                                   |
|   (search/filter/color/   |   Request Editor | Response Viewer|
|    comments)              |                                   |
+---------------------------+                                   |
|                           +-----------------------------------+
|   History Panel           |   Status Bar: Size / Time / Status|
|   (double-click to load)  |                                   |
+---------------------------+-----------------------------------+
```

- **Top-left**: Request list panel, showing all received/created requests
- **Bottom-left**: History panel, showing replay history for the selected request
- **Right**: Request editor and response viewer with layout switching
- **Bottom**: Status bar showing request/response basic information

### 2.2 Configuration Tab

Contains multiple sub-tabs:

- **Storage Config**: Database path, storage mode, auto-save parameters
- **Logging**: Log level, file logging, UI logging, Burp console logging
- **Proxy Debugging**: HTTP proxy configuration
- **Data Import/Export**: ERM archive / Postman Collection import/export
- **API Rule Config**: CRUD operations for global and project rules
- **Privilege Testing**: Token Schemes / Token Locations / User Sessions / Judgment Rule Groups / Request Scope / Replay Config / Dedup Config

### 2.3 Log Tab

Displays plugin runtime logs with level filtering support.

---

## 3. Request Management

### 3.1 Sending Requests to the Plugin

Right-click on any HTTP request in Burp Suite and select **"Send to Repeater Manager"**. Supported locations include:

- Proxy → HTTP History
- Proxy → Intercept
- Intruder
- Scanner
- Repeater (native)
- Spider

### 3.2 Creating a New Blank Request

Click the **"New Request"** button at the top-right to create a default GET request template:

```
GET / HTTP/1.1
Host: example.com
```

### 3.3 Request List Operations

- **Select request**: Click a request in the list to load its content and history on the right
- **Color marking**: Right-click a list entry to choose a color for categorization (e.g., red=high risk, green=normal)
- **Add comments**: Add text descriptions to requests for later reference
- **Search and filter**: Enter keywords in the search box to quickly locate requests
- **Column display control**: Right-click the header to open the column control dialog and customize visible columns
- **Delete request**: Right-click and select delete to clean up unwanted requests

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

Click the **"Clear"** button to clear the current request and response content.

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

### 5.4 Advanced Search

Right-click the history panel and select **"Advanced Search"**:

- Supports multi-condition composite filtering (status code, response length, time range, etc.)
- Quickly locate specific history records

### 5.5 Data Persistence

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
| Log Level | DEBUG / INFO / SUCCESS / WARN / ERROR |
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

ERM (Repeater Manager) is the plugin's native archive format, containing the complete database and body data.

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
├── repeater_manager_config.properties     # Plugin configuration file
├── repeater_manager/
│   └── api_extraction_rules.yaml          # Global API extraction rules (cross-session)
└── session_20240101_120000/               # Session directory (timestamp-named)
    ├── repeater_manager.sqlite3           # SQLite database file
    ├── blobs/                             # External body data directory
    └── logs/                              # Log files directory
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

## 10. API Rule Extraction

### 10.1 Feature Overview

The API rule extraction engine can automatically extract standardized API paths from irregular HTTP requests, making it easier to organize and manage large numbers of requests. For example, extracting `/api/v1/users/{id}/detail` from `/api/v1/users/12345/detail`.

### 10.2 Rule Types

- **Global Rules**: Stored in `~/.burp/repeater_manager/api_extraction_rules.yaml`, shared across sessions, using negative IDs
- **Project Rules**: Stored in the session SQLite database's `api_extraction_rules` table, only available in the current session, using positive IDs

### 10.3 Extraction Sources

| Source | Description |
|--------|-------------|
| URL_PATH | Extract from URL path |
| URL_QUERY | Extract from URL query parameters |
| HEADER | Extract from request headers |
| BODY | Extract from request body |

### 10.4 Extraction Methods

| Method | Description | Example |
|--------|-------------|---------|
| REGEX | Regular expression matching | `^/api/(.*)$` |
| SUBSTR | Substring extraction | `start:end` or `start,length` |
| JSON_PATH | JSONPath expression | `$.data.api_path` |
| XPATH | XPath expression | `//api/@path` |

### 10.5 Rule Priority

Global and project rules are sorted by the `priority` field, using a **first-match-wins** strategy, meaning the first matching rule takes effect.

### 10.6 Usage

1. Navigate to **"Configuration"** → **"API Rule Config"** tab
2. Click **"Add Rule"**, choose global or project rule
3. Configure rule name, extraction source, extraction method, match expression, and priority
4. Save the rule
5. Right-click in the request list and select **"Re-extract API"**, or auto-trigger re-extraction when rules change

---

## 11. Privilege Testing

### 11.1 Feature Overview

The privilege testing module provides automated horizontal/vertical privilege escalation vulnerability detection. It supports a **3-tier architecture** (Token Location → Token Scheme → User Session), uses a **single active rule group** mechanism with AND/OR/NOT multi-condition judgment, and features a three-layer fallback judgment engine (active rule group → default similarity → status code).

Key capabilities:
- **Token Scheme Management**: Group token locations into reusable schemes, bridging locations and sessions
- **User Session Management**: Configure sessions for users with different privilege levels
- **Rule Group Judgment**: Single active rule group + AND/OR/NOT condition combinations
- **Anonymous User Creation**: One-click guest user with all empty token values
- **Dedup Configuration**: Priority-chain API deduplication with 6 strategies × 3 keep policies
- **Session Parsing**: Auto-parse user sessions from clipboard (raw HTTP / Chrome fetch format)

### 11.2 Token Scheme Management

**Concept**: A token scheme is a named group of token locations, serving as an intermediate layer between token locations and user sessions. Different schemes correspond to different security testing targets (e.g., testing only Bearer authentication, testing only Cookie authentication, etc.).

**Scheme Operations**:
- **Create**: Define a scheme name, description, and select associated token locations
- **Edit**: Modify scheme name, description, or location membership
- **Delete**: Remove a scheme (associated sessions are unaffected; their location bindings persist)
- **Enable/Disable**: Toggle scheme availability
- **Persist to Global**: Save scheme to `~/.burp/repeater_manager/token_schemes.yaml` for cross-project reuse

**Session-to-Scheme Association**:
- Each user session is associated with one token scheme
- Token values in the session are filled according to the locations defined in the scheme
- Changing a scheme's locations automatically affects all sessions associated with that scheme

**Global Scheme Synchronization**:
- On startup, the plugin automatically loads global schemes from YAML into the project database
- Schemes marked as `persistToGlobal=true` are synced to YAML on save

**Configuration Examples**:
| Scheme Name | Token Locations | Use Case |
|-------------|----------------|----------|
| Bearer Auth | Authorization Header only | Testing JWT/Bearer token replacement |
| Cookie Session | Cookie: JSESSIONID | Testing session cookie hijacking |
| Hybrid Auth | Authorization Header + CSRF Token | Testing APIs requiring multiple auth factors |
| API Key | URL Param: api_key | Testing API key leakage scenarios |

### 11.3 Token Location Configuration

Configure where tokens are located in the request. The plugin supports **6 token location types**:

| Location Type | Description | Expression Example |
|---------------|-------------|-------------------|
| HEADER | Request header value | `Authorization` (extracts value after header name) |
| JSON_BODY | JSON body field | `$.access_token` (JSONPath expression) |
| XML_BODY | XML body node | `//auth/token` (XPath expression) |
| FORM_FIELD | URL-encoded form field | `csrf_token` (field name) |
| MULTIPART_FIELD | Multipart form field | `session_id` (field name) |
| URL_PARAM | URL query parameter | `token` (parameter name) |

**Additional Features**:
- **Persist to Global**: Save location to `~/.burp/repeater_manager/token_locations.yaml` for cross-project sharing
- **Enable/Disable**: Temporarily disable a location without deleting it
- **Expression Support**: JSON_BODY and XML_BODY types support JSONPath/XPath expressions for extracting tokens from complex nested structures

### 11.4 Judgment Rule Group Configuration

#### Core Concept Change (v2.30.0+)

The judgment system has been refactored from "multi-condition AND/OR combination" to **"Rule Group + Single Active Rule Set"**:

- **Rule Group**: A named collection of conditions combined with **AND** logic — all conditions within a group must be satisfied simultaneously for the group to match
- **Single Active Rule Set**: Only **one** rule group is "active" at any given time; the judgment engine evaluates only the active group
- **Fallback**: When no active rule group exists or the active group doesn't match → fallback to default similarity judgment (`SIMILARITY >= 0.90`)

**Condition Operators**:

| Operator | Description | Behavior |
|----------|-------------|----------|
| AND | All conditions must match | Default operator within a rule group |
| OR | Any condition matches | Used for alternative detection paths |
| NOT | Negate condition result | Invert match (e.g., status NOT 200) |

**Judgment Targets & Methods**:

| Target | Available Methods | Description |
|--------|-------------------|-------------|
| STATUS_CODE | EQUALS, NOT_EQUALS, GREATER_THAN, LESS_THAN | HTTP status code matching |
| RESPONSE_BODY | CONTAINS, NOT_CONTAINS, REGEX, LENGTH_DIFF | Response body content analysis |
| RESPONSE_HEADER | CONTAINS, NOT_CONTAINS, REGEX | Response header field matching |
| RESPONSE_TIME | GREATER_THAN, LESS_THAN, NUMERIC_EQUALS | Response time threshold detection |
| SIMILARITY | GREATER_THAN, LESS_THAN, NUMERIC_EQUALS | Response similarity score comparison |

#### 11.4.1 Rule Configuration Cases

Each case below corresponds to one rule group. Groups marked with `[NOT]` demonstrate the negation operator.

**Case 1: Status Code Anomaly Detection**
- **Scenario**: Normal user gets 200 but low-privilege user gets 200 with sensitive data
- **Conditions**: `STATUS_CODE EQUALS 200`
- **Note**: Simplest check; combine with body content detection for better accuracy

**Case 2: Unauthorized Access Detection (Body Keywords)**
- **Scenario**: Verify that sensitive pages return proper rejection messages
- **Conditions**: `RESPONSE_BODY NOT_CONTAINS "unauthorized"` AND `RESPONSE_BODY NOT_CONTAINS "forbidden"`
- **Note**: If 200 is returned without any rejection keywords, unauthorized access may exist

**Case 3: Sensitive Data Leakage Detection**
- **Scenario**: Test if low-privilege users can access admin-only data fields
- **Conditions**: `RESPONSE_BODY CONTAINS "admin"` OR `RESPONSE_BODY CONTAINS "superuser"`
- **Note**: If response contains admin-related data, privilege escalation is confirmed

**Case 4: Response Length Anomaly Detection**
- **Scenario**: Detect large bodies suggesting excessive data exposure
- **Conditions**: `RESPONSE_BODY LENGTH_DIFF > 500`
- **Note**: Length difference > 500 characters compared to baseline; tune threshold per application

**Case 5: High-Similarity Response with Status 200**
- **Scenario**: Detect when different users get identical successful responses
- **Conditions**: `SIMILARITY > 0.95` AND `STATUS_CODE EQUALS 200`
- **Note**: High similarity + success status = likely accessing same privileged data

**Case 6: Response Time Anomaly**
- **Scenario**: Detect processing anomalies that may indicate data retrieval
- **Conditions**: `RESPONSE_TIME LESS_THAN 500`
- **Note**: Low-privilege users getting fast responses may indicate no authorization checks

**Case 7: Header-Based Detection**
- **Scenario**: Detect redirect or authentication headers in response
- **Conditions**: `RESPONSE_HEADER CONTAINS "Location: /login"` NOT
- **Note**: If no redirect to login page, the resource may be accessible without auth

**Case 8 (NEW): Anonymous User Unauthorized Access**
- **Scenario**: Anonymous user (all tokens empty) accessing authenticated endpoints
- **Conditions**: `STATUS_CODE EQUALS 200` AND `RESPONSE_BODY NOT_CONTAINS "please login"` (via NOT operator)
- **Note**: Server should return 401/403 or page with "please login" message; if 200 is returned directly, an unauthorized access vulnerability exists

#### 11.4.2 Active Rule Group Management

- **Setting Active**: In the judgment rule table, check the **"Active"** column for the desired rule group
- **Global Uniqueness**: Setting a new active rule group automatically deactivates all other groups
- **Visual Feedback**: The active rule group is highlighted with a special style in the table
- **No Active Group**: When no active rule group exists, judgment falls back to default similarity (`SIMILARITY >= 0.90`)
- **Quick Switching**: Switch between rule groups (e.g., "strict detection" vs "lenient detection") for different testing scenarios

#### 11.4.3 Rule Reuse

- Rule groups can be set as **global rules** (`global=true`) for cross-project sharing
- Support **YAML export/import** for cross-session reuse and team sharing (auto-dedup on import)
- Recommended practice: Build a collection of rule groups for typical privilege escalation scenarios, then import directly for similar targets

### 11.9 Request Scope Configuration

Specify URL patterns to test. Only requests matching the scope will be intercepted and tested.

### 11.6 Anonymous User

**Feature Overview**: One-click creation of a guest user with all token values empty, used for unauthorized access testing.

**Workflow**:
1. Navigate to **"Configuration"** → **"Privilege Testing"** → **"User Sessions"** tab
2. Click the **"Add Anonymous User"** button
3. The system performs intelligent token scheme matching:
   - **Priority 1**: Reuse an existing user's token scheme (if any user already has a scheme)
   - **Priority 2**: Auto-match the single enabled scheme
   - **Priority 3**: Show a selection dialog when multiple schemes exist

**Empty Token Value Semantics**: All token values for the anonymous user are empty strings. During request replay:
- **HEADER**: Remove the header entirely (rather than setting an empty value)
- **JSON_BODY**: Remove the JSON property
- **XML_BODY**: Remove the XML node
- **FORM_FIELD / MULTIPART_FIELD**: Remove the form field
- **URL_PARAM**: Remove the URL query parameter

> This "removal" semantics simulates the unauthenticated state where authentication parameters are completely absent, which is closer to a real unauthorized access scenario than setting empty string values.

**Use Cases**:
- Unauthorized access testing (detecting if authentication is required)
- Guest permission boundary testing (can anonymous users see data that should be hidden?)
- Missing authentication detection on API endpoints

### 11.7 Dedup Configuration

**Feature Overview**: Prevent the same API from being tested for privilege escalation multiple times, improving automated testing efficiency.

**Core Concepts**:
- **Dedup Strategy (DedupStrategy)**: Defines how to extract a dedup key from a request (6 types)
- **Keep Policy (DedupKeepPolicy)**: Defines which request to keep among duplicates (3 types)
- **Priority-Chain Matching**: Traverses all enabled configs from highest to lowest priority; the first config that successfully extracts a dedup key is used

**6 Dedup Strategies**:

| Strategy | Description | Expression Example |
|----------|-------------|-------------------|
| PATH | Deduplicate by URL path | (no expression needed) |
| API | Deduplicate by extracted API path | (no expression needed) |
| JSON_BODY_FIELD | Deduplicate by JSON body field value | `user_id` |
| XML_BODY_FIELD | Deduplicate by XML body node value | `//user/id` |
| FORM_FIELD | Deduplicate by form field value | `order_id` |
| URL_PARAM | Deduplicate by URL parameter value | `page` |

**3 Keep Policies**:

| Policy | Description |
|--------|-------------|
| FIRST | Keep the first matching request; skip subsequent duplicates |
| LAST | Keep the last matching request; overwrite previous ones |
| MIDDLE | Keep the middle-positioned request (median index) |

**Storage Modes**:
- **Global Persistence**: Configs stored in `~/.burp/repeater_manager/dedup_configs.yaml`, shared across sessions
- **Session Temporary**: Only effective for the current session; cleared on restart

### 11.8 Session Parsing

**Feature Overview**: Automatically parse user session token values and locations from clipboard HTTP messages, greatly simplifying session configuration.

**Supported Formats**:
1. **Raw HTTP Request**: Standard HTTP request message (e.g., copied from Burp Proxy)
2. **Chrome "Copy as fetch"**: Chrome DevTools Network panel fetch copy format
3. **Chrome "Copy as fetch (Node.js)"**: Node.js-compatible fetch copy format

**Workflow**:
1. Copy the target request from Burp Proxy or Chrome DevTools
2. Navigate to **"Configuration"** → **"Privilege Testing"** → **"User Sessions"** tab
3. Click the **"Parse from Clipboard"** button
4. The plugin auto-detects clipboard format and converts it to raw HTTP
5. Automatically extracts token values and location information
6. Select the target token scheme (a selection dialog appears if no matching scheme exists)
7. Confirm to create or update the user session

> Chrome fetch format support includes single/double quotes, escape sequences, nested objects, and other complex JS syntax parsing.

### 11.10 Execute Test

1. After completing the above configuration, set an **active rule group** in the privilege testing panel (check the "Active" column for the target rule group)
2. Enable the **"Auto-testing"** switch
3. The plugin intercepts scope-matched proxy traffic
4. Automatically replaces tokens and replays requests (anonymous user's empty token values trigger "removal" operations)
5. Evaluates privilege escalation risk based on the active rule group (all conditions AND-matched → ESCALATED; any condition fails → fallback to similarity judgment)
6. View results in the **"Privilege Test"** panel:
   - **Red**: Potential privilege escalation, requires manual confirmation
   - **Green**: Safe, no privilege escalation detected

> **Three-Layer Judgment Flow**: ① Baseline response invalid → marked "ERROR"; ② Active rule group exists and all conditions match → marked "ESCALATED"; ③ No active group or mismatch → fallback to default similarity judgment (≥ threshold → ESCALATED, < threshold → NOT_ESCALATED).

> **Default Similarity Rule**: On first startup, the system auto-creates a "Default Similarity Rule Group" (lowest priority) with condition `SIMILARITY >= 0.90`. When no active rule group exists or the active group doesn't match, this fallback rule group takes effect. Users can view, edit, activate, disable, or delete this rule group in the "Judgment Rules" tab.

---

## 12. Message Comparison

### 12.1 Feature Overview

The message comparison module provides diff comparison capabilities for request/response pairs, supporting comparison of original requests with token-replaced requests and their corresponding responses in privilege testing scenarios. It also supports comparing any two history records for the same request.

### 12.2 Starting a Comparison

- Select one or more records in the history panel, right-click and choose **"Compare Messages"** to open the comparison dialog
- Select two history records and right-click to directly compare their requests and responses
- Supports **Tab mode**: Request diff and response diff viewed in separate tabs
- Supports **Four-pane mode**: Original request, replaced request, original response, replaced response displayed simultaneously

### 12.3 Diff Display

- **Green**: Added content
- **Red**: Deleted content
- **Yellow**: Modified content
- Supports character-level inline diff highlighting, implemented by DiffEngine based on an LCS (Longest Common Subsequence) algorithm variant
- Uses RSyntaxTextArea for HTTP syntax highlighting

### 12.4 Synchronized Scrolling

- Original and replacement panels are automatically synchronized via SynchronizedScrollPanel
- Context consistency is maintained when comparing large messages, preventing misalignment

### 12.5 Diff Navigation

- Use DiffNavigator's **Previous Diff** / **Next Diff** buttons for quick navigation
- Current diff region is automatically highlighted
- Total diff count and current position displayed at the top

### 12.6 Search

- Use the collapsible SearchBar to search for keywords in diff content
- Supports plain text search and regular expression search
- Search results highlighted with navigation between matches

---

## 13. Batch Operations

### 13.1 Feature Overview

Batch operations allow processing multiple history records simultaneously, significantly improving testing efficiency and suitable for handling large volumes of requests.

### 13.2 Multi-selection

- Hold **Ctrl** and click to select non-contiguous entries in the history panel
- Hold **Shift** and click to select a contiguous range of entries
- Selected count displayed with visual feedback

### 13.3 Batch Replay

- Select multiple records and right-click to choose **"Batch Replay"**
- The plugin sequentially resends all selected requests (async concurrent processing, non-blocking UI)
- Replay results are automatically appended to the history panel

### 13.4 Batch Privilege Testing

- Select multiple records and right-click to choose **"Batch Privilege Test"**
- Automatically iterates through all configured user sessions for privilege escalation detection
- Test results are aggregated in the privilege test panel for unified analysis

### 13.5 Batch Delete

- Select multiple records and right-click to choose **"Delete"**
- One-click cleanup of unwanted history records
- Delete operations trigger GC queue, automatically cleaning up associated Pool data

---

## 14. Report Export

### 14.1 Feature Overview

The report export module uses the Template Method design pattern to export privilege testing results in multiple formats, facilitating delivery, archiving, and team sharing. Report generation is based on a unified data model (`ReportData`), dispatched by `ReportExporter`, supporting both plaintext and encrypted export modes.

### 14.2 Export Operation

1. After completing tests in the privilege test panel, click the **"Export Report"** button
2. Select export format: PDF / HTML / Markdown / ERMR (encrypted container)
3. Choose the file save path
4. If ERMR encryption mode is selected, enter a password (AES-256-CBC encryption)
5. The plugin generates the report
6. HTML format reports automatically open in the browser after generation

### 14.3 Report Formats

| Format | Extension | Description | Implementation |
|--------|-----------|-------------|----------------|
| PDF | `.pdf` | Apache PDFBox 3.0.1 native generation, embedded Chinese fonts, suitable for formal delivery | `PdfReportGenerator` |
| HTML | `.html` | FreeMarker template rendering, visually appealing, view in browser | `HtmlReportGenerator` |
| Markdown | `.md` | FreeMarker template generating plain text reports, suitable for version control management | `MarkdownReportGenerator` |
| ERMR (Encrypted Container) | `.ermr` | Packages any report format into AES-256-CBC + HMAC-SHA256 encrypted archive, suitable for secure transmission | `ReportExporter` (dispatcher) |

> ERMR container mode can be layered on top of PDF/HTML/Markdown to generate `.ermr` encrypted files, ensuring the security of sensitive report data during transmission and storage.

### 14.4 Report Content

**Test Summary**:
- Test time, target scope, total requests, privilege escalation findings
- Baseline user name and the configured active rule group name

**Session Statistics**:
- Aggregated test result statistics for each user session
- Judgment results use Chinese display names:

| Enum Value | Report Display | Meaning |
|------------|---------------|---------|
| `ESCALATED` | ⚠ Escalated (越权) | Privilege escalation risk detected, requires manual confirmation |
| `NOT_ESCALATED` | ✔ Safe (安全) | No privilege escalation detected |
| `ERROR` | ✗ Error (错误) | Judgment process error (e.g., invalid baseline response) |
| `PENDING` | Pending (待判定) | Judgment not yet complete (e.g., status code difference needs manual review) |

> Report templates use the `JudgmentResult.toDisplayName()` method to uniformly convert enum values to Chinese display names, ensuring raw enum strings like `"ESCALATED"` never appear in reports.

**Per-Endpoint Details** (each tested API endpoint includes):
- Original request/response and token-replaced request/response details
- Matched **rule group name** (`matchedRuleName`): When judgment is triggered by a rule group, the report explicitly displays the matched rule group name for traceability
- Similarity score (`similarity`): Percentage of similarity between original and replaced responses
- HTTP status code, response length, response time

**Reproduction Commands**:
- **cURL Commands**: Equivalent cURL commands for each test (generated by `CurlBuilder`)
- **Postman Snippets**: Postman code snippets for each test (generated by `PostmanSnippetBuilder`), importable directly into Postman for reproduction

### 14.5 Content Rendering

- Request/response bodies automatically rendered (`BodyRenderer`)
- Binary content (images, serialized data, etc.) automatically converted to hex or base64 text display (`BinaryContentRenderer`)
- Text content maintains original formatting and syntax highlighting
- In PDF reports, excessively long text (such as Base64 strings) is automatically truncated with a prompt to view the HTML report for full data

### 14.6 Sensitive Data Warning

When exporting reports, the plugin displays a sensitive data warning dialog, indicating that the report will contain complete request/response data (which may include Bearer Tokens, Session Cookies, and other sensitive information). Recommendations:
- Use ERMR encrypted container mode to protect report data
- Review reports for unmasked authentication information before delivery
- Use strong passwords to encrypt ERMR files

---

## 15. Advanced Tips

### 15.1 HTTPS Request Handling

The plugin automatically preserves HTTPS protocol information:

- Requests sent from the context menu retain original protocol information
- HTTPS protocol is not lost when resending saved requests
- Supports port number recognition in the Host header (e.g., :443 → HTTPS)

### 15.2 Request Timeout Settings

The request editor provides timeout configuration for customizing request timeout duration.

### 15.3 Cross-session Data Migration

Use the ERM archive format for cross-session data migration:

1. Export ERM archive from the old session
2. Switch sessions or restart Burp Suite
3. Import ERM archive in the new session

### 15.4 Team Collaboration

- Export ERM archives (with optional encryption) to share with team members
- Export Postman Collections for sharing with team members who don't use Burp
- Encrypted archives use AES-256-CBC to ensure secure data transfer
- Global API extraction rules are shared via YAML files

---

## 16. FAQ

### Q: I can't see the "Repeater Manager" tab after loading the plugin?

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
