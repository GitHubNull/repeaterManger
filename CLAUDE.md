# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enhanced Repeater Manager is a Burp Suite Professional extension that provides advanced HTTP request replay capabilities with persistent storage, history tracking, and enhanced organization features. The plugin is designed for security testers and penetration testers to efficiently manage and organize HTTP/HTTPS requests.

- **Version**: 1.5.1
- **Java**: 8 (source/target compatibility)
- **Build**: Maven
- **License**: Apache License 2.0

## Architecture

The project follows a layered architecture:
```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager
+---------------------+
|   Data Storage      |  SQLite + File Blobs (Pool Dedup)
+---------------------+
```

Key components:
- **BurpExtender.java**: Entry point implementing Burp Suite extension interface (`IBurpExtender`)
- **EnhancedRepeaterUI.java**: Main UI controller that orchestrates all components (implements `ITab`)
- **DatabaseManager.java**: Singleton managing SQLite connections (connection pool via `BlockingQueue` + JDK dynamic proxy), Schema initialization, session management
- **PoolManager.java**: Content deduplication manager using SHA-256 hash-based pools
- **RequestManager.java**: Async HTTP request sender with callback interface
- **HistoryRecordingService.java**: Singleton async queue-based history recording service
- **GarbageCollectorService.java**: Background GC for zero-reference pool data cleanup
- **AutoSaveService.java**: Scheduled database checkpoint service
- **LogManager.java**: Multi-channel log dispatcher with level filtering (Burp console / rolling file / UI panel)
- **ErmArchiveWriter/Reader.java**: Custom binary archive format with optional AES-256-CBC + HMAC-SHA256 encryption
- **DatabaseConfig.java**: Configuration management (storage mode / logging / proxy)
- **PopMenu.java**: Context menu factory ("Send to Enhanced Repeater")

## Key Features

1. Request Management: Organize and categorize HTTP requests with color marking and comments
2. History Tracking: Automatic recording of request response history for comparison
3. Data Persistence: All requests and history saved to SQLite database with Pool deduplication
4. Content Deduplication: Pool architecture (string_pool/header_pool/body_pool/file_pool) with ref_count tracking
5. Advanced Search: Multi-condition filtering to quickly locate requests/responses
6. Column Display Control: Customizable table columns for better information density
7. Data Import/Export: ERM encrypted archives and Postman Collection v2.1 support
8. Auto-save: Periodic database checkpoint synchronization
9. Garbage Collection: Background cleanup of zero-reference pool data
10. Logging: Multi-channel logging (Burp console / rolling file / UI panel) with level filtering
11. Proxy Debugging: Configurable HTTP proxy for request debugging
12. Layout Switching: Horizontal/vertical/request-only/response-only layout modes

## Build Commands

To build the project:
```bash
# Using the provided build scripts
./script/build.sh        # On Linux/macOS
script\build.bat         # On Windows

# Or using Maven directly
mvn clean package
```

The build process creates two JAR files:
- Development version: `target/enhanced-repeater-1.5.1.jar`
- Timestamped release: `target/releases/enhanced-repeater-1.5.1-YYYYMMDD-HHMMSS.jar`

## Source Code Organization

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Extension entry point (must be in burp package)
└── oxff/top/
    ├── EnhancedRepeaterUI.java         # Main UI controller (ITab implementation)
    ├── config/                        # Configuration management
    │   ├── DatabaseConfig.java         # Storage mode / logging / proxy config
    │   └── SessionDirectory.java       # Session directory (timestamp-named)
    ├── controller/                    # Context menu handlers
    │   └── PopMenu.java               # "Send to Enhanced Repeater" context menu
    ├── db/                            # Database access layer
    │   ├── DatabaseManager.java        # Singleton: connection pool + Schema init
    │   ├── HistoryDAO.java             # History CRUD operations
    │   ├── RequestDAO.java             # Request CRUD operations
    │   └── pool/                      # Pool deduplication subsystem
    │       ├── PoolManager.java        # Central dedup manager
    │       ├── BodyStorageRoute.java   # Inline vs file storage routing
    │       ├── ContentHasher.java      # SHA-256 hashing
    │       ├── ContentSplitter.java    # Request/response splitting
    │       ├── ContentReconstructor.java # Content reconstruction from pools
    │       ├── FileStorageManager.java # File-based body storage (blobs/)
    │       ├── HttpEnum.java           # HTTP-related enums
    │       └── SplitResult.java        # Split operation result
    ├── http/                          # HTTP processing
    │   ├── ProxyConfig.java            # HTTP proxy configuration (singleton)
    │   ├── RequestManager.java         # Async HTTP request sender
    │   └── RequestResponseRecord.java  # Request-response data model
    ├── io/                            # Data import/export
    │   ├── DataExporter.java           # Export dispatcher
    │   ├── DataImporter.java           # Import dispatcher (smart format detection)
    │   ├── ErmArchiveWriter.java       # ERM archive export (AES-256 encryption)
    │   ├── ErmArchiveReader.java       # ERM archive import
    │   ├── ErmCryptoHelper.java        # PBKDF2 / AES-CBC / HMAC-SHA256
    │   ├── ErmFormatConstants.java     # ERM format constants (magic/offsets/sizes)
    │   ├── FormatDetector.java         # Auto-detect import file format
    │   ├── PostmanExporter.java        # Postman Collection v2.1 export
    │   └── PostmanImporter.java        # Postman Collection v2.1 import
    ├── logging/                       # Logging subsystem
    │   ├── LogManager.java             # Singleton: multi-channel log dispatcher
    │   ├── LogEntry.java               # Log entry data class
    │   ├── LogHandler.java             # Abstract log handler
    │   ├── LogLevel.java               # DEBUG / INFO / SUCCESS / WARN / ERROR
    │   ├── BurpConsoleHandler.java     # Burp console output handler
    │   ├── RollingFileHandler.java     # Rolling file log handler
    │   └── UIHandler.java              # UI panel log handler
    ├── model/                         # Data models
    │   ├── HistoryRecord.java
    │   ├── RequestRecord.java
    │   └── RequestResponseRecord.java
    ├── service/                       # Background services
    │   ├── AutoSaveService.java        # Scheduled database checkpoint
    │   ├── GarbageCollectorService.java # Zero-ref pool cleanup (10min interval)
    │   └── HistoryRecordingService.java # Async queue-based history recording
    ├── ui/                            # User interface components
    │   ├── BurpRequestPanel.java       # Burp-style request editor
    │   ├── BurpResponsePanel.java      # Burp-style response viewer
    │   ├── ConfigPanel.java            # 4-tab config panel (storage/log/proxy/IO)
    │   ├── EnhancedRequestPanel.java   # Enhanced request panel
    │   ├── EnhancedResponsePanel.java  # Enhanced response panel
    │   ├── HistoryPanel.java           # History list panel
    │   ├── HttpEditorPanel.java        # HTTP editor base panel
    │   ├── HttpViewerPanel.java        # HTTP viewer panel
    │   ├── LogPanel.java               # Log display panel
    │   ├── MainUI.java                 # Main UI (legacy, used for data refresh)
    │   ├── RequestListPanel.java       # Request list with search/filter/color
    │   ├── RequestPanel.java           # Request detail panel
    │   ├── ResponsePanel.java          # Response display panel
    │   ├── StatusPanel.java            # Bottom status bar
    │   ├── viewer/                     # HTTP viewer components
    │   │   ├── HttpViewer.java
    │   │   ├── HttpViewerPanel.java
    │   │   └── ViewMode.java           # VIEW_MODE enum
    │   └── layout/
    │       └── LayoutManager.java      # Layout switcher (HORIZONTAL/VERTICAL/REQUEST_ONLY/RESPONSE_ONLY)
    └── utils/
        └── TextLineNumber.java         # Line number utility for text components
```

## Database Schema

Two main tables + four pool tables + GC queue:

**Main tables**:
- `requests`: HTTP request metadata with hash references to pools (v2 schema with INTEGER enums)
- `history`: Request/response history with timing and status info

**Pool tables** (deduplication):
- `string_pool`: Domain/path/query strings (hash → value, ref_count)
- `header_pool`: HTTP headers (hash → BLOB data, ref_count)
- `body_pool`: Small body data inline (hash → BLOB data, ref_count, is_binary)
- `file_pool`: Large body data external (hash → relative_path, ref_count, is_binary)

**System tables**:
- `gc_queue`: Garbage collection queue (pool_type, hash)
- `schema_meta`: Metadata (schema_version, clean_shutdown)

SQLite is used with a custom connection pool (BlockingQueue + JDK Proxy for transparent connection reuse). Pool size: 5 connections. PRAGMA settings: journal_mode=DELETE, synchronous=NORMAL, foreign_keys=ON.

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Burp Suite Extender API | 2.1 | Required extension interface |
| RSyntaxTextArea | 3.3.3 | Syntax highlighting editor |
| SQLite JDBC | 3.42.0.0 | Local data persistence |
| HikariCP | 5.0.1 | Declared but not actively used (custom pool instead) |
| Gson | 2.10.1 | JSON serialization (ERM manifest, Postman export) |
| Apache Commons IO | 2.11.0 | File I/O utilities |
| Apache Commons Lang | 3.12.0 | String/object utilities |

## Configuration

Configuration is stored in `~/.burp/repeater_manager_config.properties` with:
- Database storage mode (auto/directory/file)
- Base directory and session file paths
- Auto-save settings and save interval
- Log level and log channel toggles
- File log settings (directory, max size, max backups)
- UI log settings (enabled, max entries)
- Burp console log toggle
- HTTP proxy settings (enabled, host, port)

Data is persisted in session directories under `~/.burp/` (timestamp-named), each containing:
- `repeater_manager.sqlite3` — Database file
- `blobs/` — External body data directory
- `logs/` — Log file directory

## Important Coding Conventions

1. **Java 8 compatibility**: No Java 9+ features beyond lambdas
2. **`burp` package must not be renamed**: Burp Suite requires the entry class in this package
3. **Swing threading**: All UI operations must run on EDT (`SwingUtilities.invokeLater`)
4. **Database access**: Use DAO classes with `try-with-resources`; connections are auto-returned to pool via proxy
5. **Logging**: Use `BurpExtender.printOutput()`/`printError()` or `LogManager` methods
6. **Singleton pattern**: DatabaseManager, LogManager, HistoryRecordingService, ProxyConfig
7. **Async operations**: HTTP requests, data loading, and history recording run on background threads
8. **HTTPS preservation**: Always use `IHttpService` when making requests to preserve HTTPS protocol info
9. **Error filtering**: `BurpExtender.shouldFilterError()` filters IntelliJ-related harmless ClassNotFoundExceptions

## CI/CD

GitHub Actions workflow (`.github/workflows/release.yml`):
- **Trigger**: Push `v*` tags (e.g., `v1.0.0`) or manual dispatch
- **Build**: JDK 8 + Maven on Ubuntu
- **Release**: Auto-creates GitHub Release with JAR attachment
- **Prerelease**: Tags with `-` suffix (e.g., `v1.0.0-beta`) are marked as prerelease
