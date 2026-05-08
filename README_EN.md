# Repeater Manager - Burp Suite Repeater Manager Plugin

<p align="center">
  <strong>Advanced HTTP request replay management plugin for Burp Suite, designed for security testers</strong>
</p>

<p align="center">
  English | <a href="./README.md">中文</a>
</p>

---

## Introduction

Repeater Manager is an advanced HTTP request replay management plugin designed for Burp Suite Professional. It provides more powerful features than the native Repeater, including request categorization, automatic response history recording and comparison, SQLite local persistence, content deduplication storage, multi-condition advanced search, multiple format import/export (ERM encrypted archives / Postman Collection), and scheduled auto-save mechanism. This plugin is particularly suitable for security testers and penetration testing experts, effectively improving the efficiency and organization of HTTP/HTTPS request testing.

> **Current Version**: v1.5.1 | **Requirements**: Burp Suite Professional + Java 8+

## Core Features

| Feature | Description |
|---------|-------------|
| Request Management | Organize and categorize HTTP requests with color marking and comments |
| History Tracking | Automatically record response history for each request, easy to compare results from different times |
| Data Persistence | All requests and history saved to SQLite database, surviving Burp Suite restarts |
| Content Deduplication | Pool architecture (string pool/header pool/body pool/file pool) for automatic deduplication |
| Advanced Search | Multi-condition composite filtering to quickly locate specific requests/responses |
| Column Display Control | Customizable table columns for better information density and readability |
| Data Import/Export | Support ERM encrypted archives, Postman Collection v2.1, and more formats |
| Auto-save | Periodic synchronization of in-memory data to disk, preventing data loss |
| Garbage Collection | Background automatic cleanup of zero-reference pool data, reclaiming storage space |
| Logging System | Multi-channel log output (Burp console/rolling file/UI panel) with level filtering |
| Proxy Debugging | Support HTTP proxy configuration for request debugging |
| Layout Switching | Request/Response panel supports horizontal/vertical/request-only/response-only layouts |

## Feature Architecture

```
Repeater Manager
├── Plugin Integration (Burp Extender API)
├── Request Management
│   ├── Request List (search/filter/color marking/comments)
│   ├── Request Editing (syntax highlighting)
│   └── Request Replay (async sending/timeout control)
├── Response Management
│   ├── Response Display (syntax highlighting)
│   └── Layout Switching (horizontal/vertical/request-only/response-only)
├── History Tracking
│   ├── Successful Request Recording
│   ├── Failed Request Recording
│   └── History Replay and Comparison
├── Data Persistence
│   ├── SQLite Storage
│   ├── Content Splitting (Pool deduplication architecture)
│   ├── File Storage (large body externalization)
│   └── Hash Verification
├── Import/Export
│   ├── ERM Archive (AES-256 encryption supported)
│   ├── Postman Collection v2.1
│   └── Smart Format Detection
├── Background Services
│   ├── Auto-save Service
│   ├── Garbage Collection Service
│   └── History Recording Service
├── Logging System
│   ├── Burp Console Output
│   ├── Rolling File Log
│   └── UI Log Panel
└── Configuration Management
    ├── Storage Config (auto/specified directory/specified file)
    ├── Logging Config
    └── Proxy Config
```

## Installation

### Prerequisites

- Burp Suite Professional
- Java 8 or higher

### Installation Steps

1. Download the latest JAR file from the [Releases](../../releases) page
2. Open Burp Suite Professional
3. Navigate to `Extender` → `Extensions` tab
4. Click the `Add` button
5. Select the downloaded JAR file in `Extension file`
6. Click `Next` to complete installation

> After the first load, the plugin automatically creates a session directory under `~/.burp/` (named with a timestamp), containing the database file, body data directory, and log directory.

## Quick Start

1. Right-click on any request in Burp Suite (e.g., Proxy, Intruder)
2. Select **"Send to Repeater Manager"**
3. Switch to the **"Repeater Manager"** tab to view and manage the request
4. Edit the request content and click **"Send"** to replay
5. View each replay's response in the history panel at the bottom left

For detailed usage instructions, please refer to:
- [Quick Start Tutorial](doc/usage_quick_en.md)
- [Detailed Usage Tutorial](doc/usage_detailed_en.md)

## Technical Architecture

```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager
+---------------------+
|   Data Storage      |  SQLite + File Blobs
+---------------------+
```

**Core Tech Stack**:

- **Frontend**: Java Swing (with RSyntaxTextArea syntax highlighting component)
- **Data Storage**: SQLite (JDBC v3.42.0.0) + HikariCP connection pool (v5.0.1)
- **Serialization**: Gson (v2.10.1)
- **Core Patterns**: MVC architecture, Singleton pattern, Observer pattern, Pool deduplication pattern

## Project Structure

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Burp extension entry point
└── oxff/top/
    ├── RepeaterManagerUI.java          # Main UI controller
    ├── config/
    │   ├── DatabaseConfig.java         # Database config (storage mode/logging/proxy)
    │   └── SessionDirectory.java       # Session directory management
    ├── controller/
    │   └── PopMenu.java               # Context menu ("Send to Repeater Manager")
    ├── db/
    │   ├── DatabaseManager.java        # Database connection management (pool/Schema init)
    │   ├── HistoryDAO.java             # History data access object
    │   ├── RequestDAO.java             # Request data access object
    │   └── pool/
    │       ├── PoolManager.java        # Pool deduplication manager
    │       ├── BodyStorageRoute.java   # Body storage routing (inline/file)
    │       ├── ContentHasher.java      # Content hash calculation
    │       ├── ContentSplitter.java    # Request/Response content splitting
    │       ├── ContentReconstructor.java # Content reconstruction
    │       ├── FileStorageManager.java # File-based body storage
    │       ├── HttpEnum.java           # HTTP enum types
    │       └── SplitResult.java        # Split result
    ├── http/
    │   ├── ProxyConfig.java            # HTTP proxy configuration
    │   ├── RequestManager.java         # HTTP request management (async sending)
    │   └── RequestResponseRecord.java  # Request-response record model
    ├── io/
    │   ├── DataExporter.java           # Export dispatcher
    │   ├── DataImporter.java           # Import dispatcher (smart format detection)
    │   ├── ErmArchiveWriter.java       # ERM archive export (AES-256 encryption)
    │   ├── ErmArchiveReader.java       # ERM archive import
    │   ├── ErmCryptoHelper.java        # ERM crypto helper (PBKDF2/AES-CBC/HMAC)
    │   ├── ErmFormatConstants.java     # ERM format constants
    │   ├── FormatDetector.java         # Automatic format detection
    │   ├── PostmanExporter.java        # Postman Collection export
    │   └── PostmanImporter.java        # Postman Collection import
    ├── logging/
    │   ├── LogManager.java             # Log manager (multi-channel/level filtering)
    │   ├── LogEntry.java               # Log entry
    │   ├── LogHandler.java             # Log handler base class
    │   ├── LogLevel.java               # Log level enum
    │   ├── BurpConsoleHandler.java     # Burp console log handler
    │   ├── RollingFileHandler.java     # Rolling file log handler
    │   └── UIHandler.java              # UI panel log handler
    ├── model/
    │   ├── HistoryRecord.java          # History record model
    │   ├── RequestRecord.java          # Request record model
    │   └── RequestResponseRecord.java  # Request-response record model
    ├── service/
    │   ├── AutoSaveService.java        # Auto-save service
    │   ├── GarbageCollectorService.java # Garbage collection service (Pool zero-ref cleanup)
    │   └── HistoryRecordingService.java # History recording service (async queue)
    ├── ui/
    │   ├── BurpRequestPanel.java       # Burp-style request editing panel
    │   ├── BurpResponsePanel.java      # Burp-style response display panel
    │   ├── ConfigPanel.java            # Configuration panel (storage/logging/proxy/IO)
    │   ├── EnhancedRequestPanel.java   # Enhanced request panel
    │   ├── EnhancedResponsePanel.java  # Enhanced response panel
    │   ├── HistoryPanel.java           # History panel
    │   ├── HttpEditorPanel.java        # HTTP editor panel base
    │   ├── HttpViewerPanel.java        # HTTP viewer panel
    │   ├── LogPanel.java               # Log panel
    │   ├── MainUI.java                 # Main UI
    │   ├── RequestListPanel.java       # Request list panel
    │   ├── RequestPanel.java           # Request detail panel
    │   ├── ResponsePanel.java          # Response panel
    │   ├── StatusPanel.java            # Bottom status bar
    │   ├── viewer/
    │   │   ├── HttpViewer.java         # HTTP viewer
    │   │   ├── HttpViewerPanel.java    # HTTP viewer panel
    │   │   └── ViewMode.java           # View mode enum
    │   └── layout/
    │       └── LayoutManager.java      # Layout manager (horizontal/vertical/request-only/response-only)
    └── utils/
        └── TextLineNumber.java         # Text line number utility
```

## Dependencies

| Dependency | Version | Description |
|------------|---------|-------------|
| burp-extender-api | 2.1 | Burp Suite Extension API |
| rsyntaxtextarea | 3.3.3 | Syntax highlighting editor component |
| sqlite-jdbc | 3.42.0.0 | SQLite JDBC driver |
| HikariCP | 5.0.1 | High-performance database connection pool |
| gson | 2.10.1 | JSON serialization/deserialization |
| commons-io | 2.11.0 | Apache file I/O utilities |
| commons-lang3 | 3.12.0 | Apache common utilities |

## Build

The project uses Maven for building:

```bash
# Using build scripts
./script/build.sh        # Linux/macOS
script\build.bat         # Windows

# Or using Maven directly
mvn clean package
```

Build artifacts:
- Development version: `target/repeater-manager-1.5.1.jar`
- Timestamped release version: `target/releases/repeater-manager-1.5.1-YYYYMMDD-HHMMSS.jar`

## Use Cases

1. **API Security Testing**: Continuously test the same API with different parameter combinations and save all test results
2. **Vulnerability Reproduction**: Record all requests and responses during vulnerability exploitation for later reproduction
3. **Security Assessment**: Organize API collections of large applications for systematic security testing
4. **Team Collaboration**: Export test data via ERM archives to share with team members
5. **Penetration Testing Documentation**: Record key requests during penetration testing for report writing
6. **Report Integration**: Export to Postman Collection format for integration with reporting tools

## Data Persistence

### Storage Modes

| Mode | Description |
|------|-------------|
| Auto (default) | Automatically creates timestamp-named session directory under `~/.burp/` |
| Specified Directory | Creates timestamp-named session directory under the specified directory |
| Specified File | Uses the specified database file directly, no timestamp subdirectory |

### Session Directory Structure

```
~/.burp/
└── session_20240101_120000/     # Session directory (timestamp-named)
    ├── repeater_manager.sqlite3 # SQLite database file
    ├── blobs/                   # External body data directory
    └── logs/                    # Log file directory
```

### Pool Deduplication Architecture

The database uses a Pool architecture for content deduplication:

- **string_pool**: Deduplication of domain/path/query strings
- **header_pool**: Deduplication of HTTP request/response headers
- **body_pool**: Deduplication of small body data (inline storage)
- **file_pool**: Deduplication of large body data (file external storage)
- **gc_queue**: Garbage collection queue, automatically cleans up zero-reference data

## Roadmap

- [ ] Add team sharing functionality for multi-user collaboration
- [ ] Integrate automated testing script support
- [ ] Provide request templates for quickly creating similar requests
- [ ] Support more data formats for import/export
- [ ] Add request sequence functionality for multi-step request workflows

## Contributing

Issues and Pull Requests are welcome. Please ensure:

1. Code style is consistent with existing code
2. New features should include documentation
3. Run `mvn clean package` before submitting to ensure the build succeeds

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Security Disclaimer

This project is intended solely for legitimate security testing and research. See [SECURITY.md](SECURITY.md) for details.
