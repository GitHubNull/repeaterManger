# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Repeater Manager is a Burp Suite Professional extension that provides advanced HTTP request replay capabilities with persistent storage, history tracking, API extraction, privilege escalation testing, and enhanced organization features. The plugin is designed for security testers and penetration testers to efficiently manage and organize HTTP/HTTPS requests.

- **Version**: 2.2.0
- **Java**: 17 (source/target compatibility)
- **Build**: Maven
- **License**: Apache License 2.0

## Architecture

The project follows a layered architecture:
```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording / ApiExtraction / PrivilegeTest
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager / ApiExtractionRuleDAO
+---------------------+
|   Data Storage      |  SQLite + File Blobs (Pool Dedup) + YAML (Global Rules)
+---------------------+
```

Key components:
- **BurpExtender.java**: Entry point implementing Montoya SDK's `BurpExtension` interface, initialized via `initialize(MontoyaApi)`
- **MontoyaApiHolder.java**: Static holder for `MontoyaApi` instance, bridges legacy static access pattern to constructor injection
- **RepeaterManagerUI.java**: Main UI controller that orchestrates all components
- **DatabaseManager.java**: Singleton managing SQLite connections (connection pool via `BlockingQueue` + JDK dynamic proxy), Schema initialization, session management
- **PoolManager.java**: Content deduplication manager using SHA-256 hash-based pools
- **RequestManager.java**: Async HTTP request sender using `MontoyaApi.http().sendRequest()`
- **HistoryRecordingService.java**: Singleton async queue-based history recording service
- **GarbageCollectorService.java**: Background GC for zero-reference pool data cleanup
- **AutoSaveService.java**: Scheduled database checkpoint service
- **LogManager.java**: Multi-channel log dispatcher with level filtering (Burp console / rolling file / UI panel)
- **ErmArchiveWriter/Reader.java**: Custom binary archive format with optional AES-256-CBC + HMAC-SHA256 encryption
- **DatabaseConfig.java**: Configuration management (storage mode / logging / proxy)
- **PopMenu.java**: Context menu provider implementing Montoya SDK's `ContextMenuItemsProvider`
- **ApiExtractionEngine.java**: Stateless rule-based API extraction engine (regex/substring/JSONPath/XPath) from URL path, query, headers, body
- **GlobalRuleManager.java**: Singleton managing global API extraction rules stored in `~/.burp/repeater_manager/api_extraction_rules.yaml`
- **ApiRuleManager.java**: Project-level API extraction rule management with SQLite persistence
- **AutoTestEngine.java**: Automated privilege escalation testing from proxy-intercepted scope-matched traffic
- **ReplayEngine.java**: Handles request replay logic for privilege testing
- **JudgmentEngine.java**: Evaluates responses against configurable rules to detect privilege escalation
- **TokenReplacementEngine.java**: Manages token substitution in requests across user sessions

## Key Features

1. **Request Management**: Organize and categorize HTTP requests with color marking and comments
2. **History Tracking**: Automatic recording of request response history for comparison
3. **Data Persistence**: All requests and history saved to SQLite database with Pool deduplication
4. **Content Deduplication**: Pool architecture (string_pool/header_pool/body_pool/file_pool) with ref_count tracking
5. **Advanced Search**: Multi-condition filtering to quickly locate requests/responses
6. **Column Display Control**: Customizable table columns for better information density
7. **Data Import/Export**: ERM encrypted archives and Postman Collection v2.1 support
8. **Auto-save**: Periodic database checkpoint synchronization
9. **Garbage Collection**: Background cleanup of zero-reference pool data (10min interval)
10. **Logging**: Multi-channel logging (Burp console / rolling file / UI panel) with level filtering
11. **Proxy Debugging**: Configurable HTTP proxy for request debugging
12. **Layout Switching**: Horizontal/vertical/request-only/response-only layout modes
13. **API Extraction**: Configurable rule engine supporting 4 extraction sources (URL_PATH, URL_QUERY, HEADER, BODY) × 4 methods (REGEX, SUBSTR, JSON_PATH, XPATH), with global rules (YAML) and project-level rules (SQLite)
14. **Privilege Escalation Testing**: Automated testing framework that intercepts scope-matched proxy traffic, replays requests with different user tokens, and judges responses against configurable rules (status code, response body/header/time comparison)

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
- Development version: `target/repeater-manager-2.2.0.jar`
- Timestamped release: `target/releases/repeater-manager-2.2.0-YYYYMMDD-HHMMSS.jar`

## Source Code Organization

```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Extension entry point (must be in burp package)
└── oxff/top/
    ├── RepeaterManagerUI.java          # Main UI controller
    ├── api/                            # API extraction subsystem
    │   ├── MontoyaApiHolder.java       # Static bridge for MontoyaApi access
    │   ├── ApiExtractionEngine.java    # Stateless rule-based extraction engine
    │   ├── ApiExtractionRule.java      # Rule model (source, method, expression, priority)
    │   ├── ApiExtractionRuleDAO.java   # Project-level rule CRUD (SQLite)
    │   ├── ApiRuleManager.java         # Project-level rule lifecycle manager
    │   ├── GlobalRuleManager.java      # Global rule manager (YAML-based)
    │   ├── ApiRuleYamlIO.java          # YAML serialization for rules
    │   ├── ApiRuleSource.java          # Enum: URL_PATH, URL_QUERY, HEADER, BODY
    │   └── ApiRuleMethod.java          # Enum: REGEX, SUBSTR, JSON_PATH, XPATH
    ├── config/                         # Configuration management
    │   ├── DatabaseConfig.java         # Storage mode / logging / proxy config
    │   └── SessionDirectory.java       # Session directory (timestamp-named)
    ├── controller/                     # Context menu handlers
    │   └── PopMenu.java                # "Send to Repeater Manager" context menu (ContextMenuItemsProvider)
    ├── db/                             # Database access layer
    │   ├── DatabaseManager.java        # Singleton: connection pool + Schema init
    │   ├── RequestDAO.java             # Request CRUD operations
    │   ├── schema/                     # Schema management
    │   │   ├── SchemaInitializer.java  # Schema creation
    │   │   └── SchemaMigrator.java     # Schema versioning and migration
    │   ├── history/                    # History DAOs (read/write/update separation)
    │   │   ├── HistoryReadDAO.java     # History read operations
    │   │   ├── HistoryWriteDAO.java    # History write operations
    │   │   └── HistoryUpdateDAO.java   # History update operations
    │   └── pool/                       # Pool deduplication subsystem
    │       ├── PoolManager.java        # Central dedup manager
    │       ├── BodyStorageRoute.java   # Inline vs file storage routing
    │       ├── ContentHasher.java      # SHA-256 hashing
    │       ├── ContentSplitter.java    # Request/response splitting
    │       ├── ContentReconstructor.java # Content reconstruction from pools
    │       ├── FileStorageManager.java # File-based body storage (blobs/)
    │       ├── HttpEnum.java           # HTTP-related enums
    │       └── SplitResult.java        # Split operation result
    ├── http/                           # HTTP processing
    │   ├── ProxyConfig.java            # HTTP proxy configuration (singleton)
    │   ├── RequestManager.java         # Async HTTP request sender (Montoya API)
    │   ├── HttpRequestHelper.java      # HTTP request parsing utilities (Montoya types)
    │   ├── RequestDataHelper.java      # Request data validation/repair utilities
    │   └── RequestResponseRecord.java  # Request-response data model
    ├── io/                             # Data import/export
    │   ├── DataExporter.java           # Export dispatcher
    │   ├── DataImporter.java           # Import dispatcher (smart format detection)
    │   ├── ErmArchiveWriter.java       # ERM archive export (AES-256 encryption)
    │   ├── ErmArchiveReader.java       # ERM archive import
    │   ├── ErmCryptoHelper.java        # PBKDF2 / AES-CBC / HMAC-SHA256
    │   ├── ErmFormatConstants.java     # ERM format constants (magic/offsets/sizes)
    │   ├── FormatDetector.java         # Auto-detect import file format
    │   ├── PostmanExporter.java        # Postman Collection v2.1 export
    │   └── PostmanImporter.java        # Postman Collection v2.1 import
    ├── logging/                        # Logging subsystem
    │   ├── LogManager.java             # Singleton: multi-channel log dispatcher
    │   ├── LogEntry.java               # Log entry data class
    │   ├── LogHandler.java             # Abstract log handler
    │   ├── LogLevel.java               # DEBUG / INFO / SUCCESS / WARN / ERROR
    │   ├── BurpConsoleHandler.java     # Burp console output handler (Montoya Logging API)
    │   ├── RollingFileHandler.java     # Rolling file log handler
    │   └── UIHandler.java              # UI panel log handler
    ├── model/                          # Data models
    │   ├── HistoryRecord.java
    │   ├── RequestRecord.java
    │   └── RequestResponseRecord.java
    ├── privilege/                      # Privilege escalation testing subsystem
    │   ├── AutoTestEngine.java         # Automated testing from proxy traffic
    │   ├── ReplayEngine.java           # Request replay logic
    │   ├── JudgmentEngine.java         # Response evaluation engine
    │   ├── TokenReplacementEngine.java # Token substitution in requests
    │   ├── LevenshteinCalculator.java  # String similarity calculation
    │   ├── SessionManager.java         # User session lifecycle manager
    │   ├── JudgmentRuleManager.java    # Judgment rule lifecycle manager
    │   ├── ScopeManager.java           # Request scope manager
    │   ├── JudgmentRuleYamlIO.java     # YAML serialization for judgment rules
    │   ├── model/                      # Privilege test models
    │   │   ├── UserSession.java        # User session (credentials/tokens)
    │   │   ├── JudgmentRule.java       # Escalation detection rule
    │   │   ├── JudgmentResult.java     # Test result
    │   │   ├── TokenLocation.java      # Token location in request
    │   │   ├── TokenLocationType.java  # Enum: HEADER, COOKIE, BODY, URL_PARAM
    │   │   ├── RuleTarget.java         # Enum: STATUS_CODE, RESPONSE_BODY, etc.
    │   │   ├── RuleMethod.java         # Enum: CONTAINS, NOT_CONTAINS, REGEX, LENGTH_DIFF
    │   │   └── ScopeEntry.java         # Scope configuration
    │   └── dao/                        # Privilege test DAOs
    │       ├── SessionDAO.java         # User session CRUD
    │       ├── JudgmentRuleDAO.java    # Judgment rule CRUD
    │       └── ScopeDAO.java           # Scope CRUD
    ├── service/                        # Background services
    │   ├── AutoSaveService.java        # Scheduled database checkpoint
    │   ├── GarbageCollectorService.java # Zero-ref pool cleanup (10min interval)
    │   └── HistoryRecordingService.java # Async queue-based history recording (Montoya types)
    ├── ui/                             # User interface components
    │   ├── MainUI.java                 # Main UI (legacy, used for data refresh)
    │   ├── RequestListPanel.java       # Request list with search/filter/color
    │   ├── RequestPanel.java           # Request detail panel
    │   ├── RequestPanelSender.java     # Request send handler (Montoya API)
    │   ├── ResponsePanel.java          # Response display panel
    │   ├── LogPanel.java               # Log display panel
    │   ├── StatusPanel.java            # Bottom status bar
    │   ├── editor/                     # Burp-style editor components
    │   │   ├── BurpRequestPanel.java   # Montoya HttpRequestEditor wrapper
    │   │   ├── BurpResponsePanel.java  # Montoya HttpResponseEditor wrapper
    │   │   ├── HttpEditorPanel.java    # HTTP editor base panel
    │   │   ├── EnhancedRequestPanel.java  # Enhanced request panel
    │   │   ├── EnhancedResponsePanel.java # Enhanced response panel
    │   │   └── HttpViewerPanel.java    # HTTP viewer panel
    │   ├── viewer/                     # HTTP viewer components
    │   │   ├── HttpViewer.java
    │   │   ├── HttpViewerPanel.java
    │   │   └── ViewMode.java           # VIEW_MODE enum
    │   ├── config/                     # Configuration UI
    │   │   ├── ConfigPanel.java        # Multi-tab config panel
    │   │   ├── StorageConfigTab.java   # Storage configuration tab
    │   │   ├── ApiRuleConfigTab.java   # API extraction rule configuration tab
    │   │   ├── ApiRuleEditDialog.java  # Rule editor dialog
    │   │   ├── ApiRuleTableModel.java  # Rule table model
    │   │   └── ApiReExtractWorker.java # Background rule re-extraction worker
    │   ├── history/                    # History UI
    │   │   ├── HistoryPanel.java       # History list with search/filter
    │   │   ├── HistoryContextMenu.java # History context menu
    │   │   ├── HistoryTableRenderer.java # History table cell renderer
    │   │   ├── AdvancedSearchDialog.java # Advanced search dialog
    │   │   └── ColumnControlDialog.java  # Column display control dialog
    │   ├── layout/                     # Layout management
    │   │   └── LayoutManager.java      # Layout switcher (HORIZONTAL/VERTICAL/REQUEST_ONLY/RESPONSE_ONLY)
    │   └── privilege/                  # Privilege test UI
    │       ├── PrivilegeTestPanel.java # Main privilege test panel
    │       ├── UserSessionTableModel.java
    │       ├── JudgmentRuleTableModel.java
    │       ├── UserSessionEditDialog.java
    │       ├── JudgmentRuleEditDialog.java
    │       ├── TokenLocationEditDialog.java
    │       └── ScopeConfigTab.java     # Scope configuration tab
    └── utils/
        └── TextLineNumber.java         # Line number utility for text components
```

## Montoya SDK API Mapping

The extension uses the Montoya SDK (`burp.api.montoya.*`) instead of the legacy Burp Extender API:

| Legacy API | Montoya SDK Equivalent |
|------------|----------------------|
| `IBurpExtender` | `BurpExtension` |
| `IBurpExtenderCallbacks` | `MontoyaApi` (obtained via `initialize()`) |
| `IExtensionHelpers` | `HttpRequest`/`HttpResponse` static factory methods |
| `IHttpRequestResponse` | `HttpRequestResponse` |
| `IHttpService` | `HttpService` |
| `IRequestInfo` | `HttpRequest` (use `.method()`, `.url()`, `.headers()`) |
| `IResponseInfo` | `HttpResponse` (use `.statusCode()`, `.headers()`) |
| `ITextEditor` | `HttpRequestEditor` / `HttpResponseEditor` |
| `IMessageEditor` | `HttpRequestEditor` / `HttpResponseEditor` |
| `ITab` | Register via `api.userInterface().registerSuiteTab()` |
| `IContextMenuFactory` | `ContextMenuItemsProvider` |
| `callbacks.makeHttpRequest()` | `api.http().sendRequest()` |
| `callbacks.createTextEditor()` | `api.userInterface().createHttpRequestEditor()` |
| `helpers.analyzeRequest()` | `HttpRequest.httpRequest(ByteArray)` |
| `helpers.buildHttpMessage()` | Manual header/body assembly + `HttpRequest.httpRequest()` |
| `helpers.buildHttpService()` | `HttpService.httpService()` |

Key Montoya types:
- `burp.api.montoya.MontoyaApi` - Main API entry point
- `burp.api.montoya.core.ByteArray` - Wraps `byte[]` for API calls (use `ByteArray.byteArray(bytes)`)
- `burp.api.montoya.http.HttpService` - HTTP service (host/port/protocol)
- `burp.api.montoya.http.message.requests.HttpRequest` - HTTP request object
- `burp.api.montoya.http.message.responses.HttpResponse` - HTTP response object
- `burp.api.montoya.http.message.HttpHeader` - HTTP header (name/value)
- `burp.api.montoya.http.message.HttpRequestResponse` - Request-response pair
- `burp.api.montoya.logging.Logging` - Logging interface (`api.logging()`)
- `burp.api.montoya.ui.editor.HttpRequestEditor` - Request editor component
- `burp.api.montoya.ui.editor.HttpResponseEditor` - Response editor component

## Database Schema

Two main tables + four pool tables + GC queue + API extraction rules:

**Main tables**:
- `requests`: HTTP request metadata with hash references to pools (v2 schema with INTEGER enums)
- `history`: Request/response history with timing and status info

**Pool tables** (deduplication):
- `string_pool`: Domain/path/query strings (hash → value, ref_count)
- `header_pool`: HTTP headers (hash → BLOB data, ref_count)
- `body_pool`: Small body data inline (hash → BLOB data, ref_count, is_binary)
- `file_pool`: Large body data external (hash → relative_path, ref_count, is_binary)

**Feature tables**:
- `api_extraction_rules`: Project-level API extraction rules (source, method, expression, priority, enabled)
- `user_sessions`: Privilege testing user sessions (credentials, token locations)
- `judgment_rules`: Privilege escalation judgment rules (target, method, threshold)
- `scopes`: Request scope patterns for automated privilege testing

**System tables**:
- `gc_queue`: Garbage collection queue (pool_type, hash)
- `schema_meta`: Metadata (schema_version, clean_shutdown)

SQLite is used with a custom connection pool (BlockingQueue + JDK Proxy for transparent connection reuse). Pool size: 5 connections. PRAGMA settings: journal_mode=DELETE, synchronous=NORMAL, foreign_keys=ON.

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| Montoya API | 2025.12 | Modern Burp Suite extension interface (provided scope) |
| RSyntaxTextArea | 3.3.3 | Syntax highlighting editor |
| SQLite JDBC | 3.42.0.0 | Local data persistence |
| HikariCP | 5.0.1 | Declared but not actively used (custom pool instead) |
| Gson | 2.10.1 | JSON serialization (ERM manifest, Postman export) |
| SnakeYAML | 2.2 | YAML serialization (API extraction rules, judgment rules) |
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

Global API extraction rules are stored in `~/.burp/repeater_manager/api_extraction_rules.yaml`.

Data is persisted in session directories under `~/.burp/` (timestamp-named), each containing:
- `repeater_manager.sqlite3` — Database file
- `blobs/` — External body data directory
- `logs/` — Log file directory

## Important Coding Conventions

1. **Java 17 compatibility**: Required by Montoya SDK; features like text blocks, sealed classes, records available
2. **`burp` package must not be renamed**: Burp Suite requires the entry class in this package
3. **Montoya SDK**: Use `burp.api.montoya.*` APIs exclusively; no legacy `burp.I*` interfaces
4. **MontoyaApi access**: Prefer constructor injection; use `MontoyaApiHolder.getApi()` as fallback for static contexts (located in `oxff.top.api` package)
5. **ByteArray wrapping**: Montoya API methods require `ByteArray.byteArray(bytes)` instead of raw `byte[]`
6. **Swing threading**: All UI operations must run on EDT (`SwingUtilities.invokeLater`)
7. **Database access**: Use DAO classes with `try-with-resources`; connections are auto-returned to pool via proxy
8. **Logging**: Use `BurpExtender.printOutput()`/`printError()` or `LogManager` methods
9. **Singleton pattern**: DatabaseManager, LogManager, HistoryRecordingService, ProxyConfig, GlobalRuleManager
10. **Async operations**: HTTP requests, data loading, history recording, API extraction, and privilege testing run on background threads
11. **HTTPS preservation**: Always use `HttpService` when making requests to preserve HTTPS protocol info
12. **Error filtering**: `BurpExtender.shouldFilterError()` filters IntelliJ-related harmless ClassNotFoundExceptions
13. **API rule IDs**: Global rules use negative IDs, project-level rules use positive IDs (stored in SQLite)
14. **YAML files**: Use SnakeYAML for reading/writing `api_extraction_rules.yaml` and judgment rule YAML files

## CI/CD

GitHub Actions workflow (`.github/workflows/release.yml`):
- **Trigger**: Push `v*` tags (e.g., `v2.2.0`) or manual dispatch
- **Build**: JDK 17 + Maven on Ubuntu
- **Release**: Auto-creates GitHub Release with JAR attachment
- **Prerelease**: Tags with `-` suffix (e.g., `v2.2.0-beta`) are marked as prerelease
