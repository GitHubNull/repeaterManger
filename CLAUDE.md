# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Repeater Manager is a Burp Suite Professional extension that provides advanced HTTP request replay capabilities with persistent storage, history tracking, API extraction, privilege escalation testing, and enhanced organization features. The plugin is designed for security testers and penetration testers to efficiently manage and organize HTTP/HTTPS requests.

- **Version**: 2.34.0
- **Java**: 17 (source/target compatibility)
- **Build**: Maven
- **License**: Apache License 2.0

## Architecture

The project follows a layered architecture:
```
+---------------------+
|      UI Layer       |  Java Swing + RSyntaxTextArea
+---------------------+
|   Service Layer     |  AutoSave / GC / HistoryRecording / ApiExtraction / PrivilegeTest / ReportGeneration
+---------------------+
|   Data Access Layer |  RequestDAO / HistoryDAO / PoolManager / ApiExtractionRuleDAO
+---------------------+
|   Data Storage      |  SQLite + File Blobs (Pool Dedup) + YAML (Global Rules)
+---------------------+
```

Key components:
- **RepeaterManagerExtension.java**: Plugin lifecycle entry point implementing Montoya SDK's `BurpExtension` interface, initialized via `initialize(MontoyaApi)` (replaced deleted `burp/BurpExtender.java`)
- **MontoyaApiHolder.java**: Static holder for `MontoyaApi` instance, bridges legacy static access pattern to constructor injection
- **RepeaterManagerUI.java**: Main UI controller that orchestrates all components
- **UIRequestDispatcher.java**: UI bridge decoupling entry class from UI operations
- **DatabaseManager.java**: Singleton managing SQLite connections (connection pool via `BlockingQueue` + JDK dynamic proxy), Schema initialization, session management, connection pool monitoring stats
- **PoolManager.java**: Content deduplication manager using SHA-256 hash-based pools
- **RequestManager.java**: Async HTTP request sender using `MontoyaApi.http().sendRequest()`
- **RequestDispatchHandler.java**: Central request dispatch handler coordinating privilege test and normal request flows
- **HistoryRecordingService.java**: Singleton async queue-based history recording service
- **GarbageCollectorService.java**: Background GC for zero-reference pool data cleanup, supports auto/manual mode toggle
- **AutoSaveService.java**: Scheduled database checkpoint service
- **LogManager.java**: Multi-channel log dispatcher with level filtering (Burp console / rolling file / UI panel), built-in GC scheduler (30s interval daemon thread)
- **ErmArchiveWriter/Reader.java**: Custom binary archive format with optional AES-256-CBC + HMAC-SHA256 encryption
- **DatabaseConfig.java**: Configuration management (storage mode / logging / proxy)
- **PopMenu.java**: Context menu provider implementing Montoya SDK's `ContextMenuItemsProvider`
- **ApiExtractionEngine.java**: Stateless rule-based API extraction engine (regex/substring/JSONPath/XPath) from URL path, query, headers, body
- **GlobalRuleManager.java**: Singleton managing global API extraction rules stored in `~/.burp/repeater_manager/api_extraction_rules.yaml`
- **ApiRuleManager.java**: Project-level API extraction rule management with SQLite persistence
- **AutoTestEngine.java**: Automated privilege escalation testing from proxy-intercepted scope-matched traffic
- **ReplayEngine.java**: Handles request replay logic for privilege testing
- **JudgmentEngine.java**: Evaluates responses using three-tier logic: invalid baseline→ERROR → active rule group match → fallback similarity judgment (v2.30.0 rule group refactor)
- **FieldReplacementEngine.java**: Manages token substitution in requests across user sessions, supports empty-value removal semantics
- **RuleCondition.java**: Rule condition model (target + method + expression + AND/OR/NOT operator + negate flag)
- **Scheme.java**: Scheme model bridging fields and user sessions
- **GlobalSchemeManager.java**: Singleton managing global scheme CRUD with YAML persistence (v2.21.0)
- **DedupConfigManager.java**: Multi-config priority-chain deduplication manager (6 strategies × 3 keep policies, v2.20.0)
- **ApiDedupEngine.java**: Stateless API dedup key extraction engine
- **FetchRequestParser.java**: Chrome DevTools "Copy as fetch" format parser (v2.26.0)
- **SimilarityEngine.java**: Content-aware similarity calculation engine (JSON/XML/generic text)
- **SyncHttpSender.java**: Synchronous HTTP sender with retry support
- **HttpMessageParser.java**: Unified HTTP message parsing utilities
- **DiffEngine.java / DiffPane.java / SearchBar.java / DiffNavigator.java**: Message comparison components with string/byte-level diff, syntax highlighting, synchronized scrolling, and change navigation (ComparisonDialog for full-featured comparison)
- **ReportGenerator.java**: Abstract base class for report generation with PdfReportGenerator (Apache PDFBox), HtmlReportGenerator, and MarkdownReportGenerator (FreeMarker templates) implementations
- **ReportExporter.java**: Unified report export dispatcher (PDF/HTML/Markdown)
- **BodyRenderer.java / BinaryContentRenderer.java**: Request/response body rendering including binary content support
- **GlobalFieldDefinitionManager.java**: Singleton managing global fields shared across sessions
- **UserSessionYamlIO.java**: YAML serialization for user session import/export
- **FileChooserHelper.java**: Unified file chooser utility for consistent file selection dialogs

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
14. **Privilege Escalation Testing**: Automated testing framework with scheme management, single-active rule group judgment (AND/OR/NOT conditions), configurable dedup, one-click anonymous user creation, and session parsing from clipboard (including Chrome DevTools fetch format)
15. **Message Comparison**: String and byte-level diff comparison between request/response pairs with syntax highlighting (RSyntaxTextArea), synchronized scrolling (SynchronizedScrollPanel), diff navigation (DiffNavigator), and in-line character-level diff highlighting via DiffEngine/DiffPane
16. **Report Generation**: Export privilege test results as PDF (Apache PDFBox with embedded Chinese fonts), HTML or Markdown (FreeMarker templates) reports with embedded request/response bodies, cURL commands, and Postman code snippets; includes binary content rendering for non-text responses
17. **Batch Operations**: Multi-select support in history and request panels; batch replay, batch privilege testing, and batch deletion of selected entries

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
- Development version: `target/repeater-manager-2.34.0.jar`
- Timestamped release: `target/releases/repeater-manager-2.34.0-YYYYMMDD-HHMMSS.jar`

## Source Code Organization

```
src/main/java/
├── org/oxff/repeater/
│   ├── RepeaterManagerExtension.java    # Plugin lifecycle entry point (replaced burp/BurpExtender.java)
│   ├── RepeaterManagerUI.java          # Main UI controller
│   ├── UIRequestDispatcher.java         # UI bridge
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
    │   ├── FieldReplacementEngine.java # Field substitution in requests
    │   ├── LevenshteinCalculator.java  # String similarity calculation
    │   ├── SessionManager.java         # User session lifecycle manager
    │   ├── JudgmentRuleManager.java    # Judgment rule lifecycle manager
    │   ├── ScopeManager.java           # Request scope manager
    │   ├── JudgmentRuleYamlIO.java     # YAML serialization for judgment rules
    │   ├── model/                      # Privilege test models
    │   │   ├── UserSession.java        # User session (credentials/tokens, schemeId)
    │   │   ├── Scheme.java         # Scheme model (v2.21.0)
    │   │   ├── JudgmentRule.java       # Escalation detection rule group (v2.30.0 refactor)
    │   │   ├── RuleCondition.java       # Rule condition (target + method + expression + AND/OR/NOT)
    │   │   ├── JudgmentResult.java     # Test result (PENDING/ESCALATED/NOT_ESCALATED/ERROR)
    │   │   ├── FieldDefinition.java      # Field definition in request
    │   │   ├── FieldType.java  # Enum: HEADER, JSON_BODY, XML_BODY, FORM_FIELD, MULTIPART_FIELD, URL_PARAM
    │   │   ├── RuleTarget.java         # Enum: STATUS_CODE, RESPONSE_HEADER, RESPONSE_BODY, RESPONSE_TIME, SIMILARITY
    │   │   ├── RuleMethod.java         # Enum: REGEX, CONTAINS, EQUALS, GREATER_THAN, LESS_THAN, NUMERIC_EQUALS, NOT_CONTAINS, NOT_EQUALS, LENGTH_DIFF
    │   │   ├── ScopeEntry.java         # Scope configuration
    │   │   ├── DedupStrategy.java       # Enum: PATH, API, JSON_BODY_FIELD, XML_BODY_FIELD, FORM_FIELD, URL_PARAM
    │   │   └── DedupKeepPolicy.java     # Enum: FIRST, LAST, MIDDLE
    │   └── dao/                        # Privilege test DAOs
    │       ├── SessionDAO.java         # User session CRUD
    │       ├── JudgmentRuleDAO.java    # Judgment rule CRUD
    │       └── ScopeDAO.java           # Scope CRUD
    │   ├── report/                      # Report generation subsystem
    │   │   ├── ReportGenerator.java     # Abstract report generator base class
    │   │   ├── PdfReportGenerator.java  # PDF report (Apache PDFBox 3.0.1)
    │   │   ├── HtmlReportGenerator.java # HTML report (FreeMarker template)
    │   │   ├── MarkdownReportGenerator.java # Markdown report (FreeMarker template)
    │   │   ├── ReportExporter.java      # Report export dispatcher
    │   │   ├── ReportData.java          # Report data model
    │   │   ├── ReportContainerWriter.java # Report container serialization
    │   │   ├── ReportContainerReader.java # Report container deserialization
    │   │   ├── BodyRenderer.java        # Body content renderer
    │   │   ├── BinaryContentRenderer.java # Binary content renderer (hex/base64/image)
    │   │   ├── CurlBuilder.java         # cURL command builder
    │   │   ├── PostmanSnippetBuilder.java # Postman code snippet builder
    │   │   └── FreeMarkerConfig.java    # FreeMarker configuration
    │   ├── UserSessionYamlIO.java       # User session YAML import/export
    │   ├── FieldDefinitionYamlIO.java     # Field definition YAML import/export
    │   └── GlobalFieldDefinitionManager.java # Global field manager
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
    │   ├── history/                    # History UI + Message comparison
    │   │   ├── HistoryPanel.java       # History list with search/filter
    │   │   ├── HistoryContextMenu.java # History context menu (batch ops, comparison)
    │   │   ├── HistoryTableRenderer.java # History table cell renderer
    │   │   ├── AdvancedSearchDialog.java # Advanced search dialog
    │   │   ├── ColumnControlDialog.java  # Column display control dialog
    │   │   ├── ComparisonDialog.java   # Message comparison dialog (tab/four-pane layout)
    │   │   ├── DiffEngine.java         # Diff algorithm engine (LCS-based, char-level inline diff)
    │   │   ├── DiffPane.java           # Self-contained diff display panel (RSyntaxTextArea)
    │   │   ├── DiffNavigator.java      # Diff region navigator (prev/next change)
    │   │   ├── SearchBar.java          # Collapsible search bar for diff content
    │   │   └── SynchronizedScrollPanel.java # Synchronized scrolling for side-by-side comparison
    │   ├── layout/                     # Layout management
    │   │   └── LayoutManager.java      # Layout switcher (HORIZONTAL/VERTICAL/REQUEST_ONLY/RESPONSE_ONLY)
    │   └── privilege/                  # Privilege test UI
    │       ├── PrivilegeTestPanel.java # Main privilege test panel
    │       ├── SessionConfigTab.java   # User session configuration tab
    │       ├── JudgmentRuleConfigTab.java # Judgment rule configuration tab
    │       ├── ScopeConfigTab.java     # Scope configuration tab
    │       ├── UserSessionTableModel.java # Session table model
    │       ├── JudgmentRuleTableModel.java # Judgment rule table model
    │       ├── FieldDefinitionTableModel.java # Field definition table model
    │       ├── UserSessionEditDialog.java # User session editor dialog
    │       ├── JudgmentRuleEditDialog.java # Judgment rule editor dialog
    │       ├── FieldDefinitionEditDialog.java # Field definition editor dialog
    │       └── FieldValueCellRenderer.java # Field value cell renderer
    ├── RequestDispatchHandler.java     # Central request dispatch handler
    └── utils/
        ├── TextLineNumber.java         # Line number utility for text components
        └── FileChooserHelper.java      # Unified file chooser utility
```
```
src/main/resources/
└── templates/
    └── report/
        ├── html_report.ftl            # HTML report FreeMarker template
        ├── md_report.ftl              # Markdown report FreeMarker template
        └── html_css.ftl               # Report CSS template

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
- `user_sessions`: Privilege testing user sessions (credentials, scheme_id, replay config fields)
- `schemes`: Scheme definitions (name, description, enabled, persist_to_global)
- `scheme_field_definitions`: Scheme-to-token-location associations
- `field_definitions`: Field definition definitions (type, expression, enabled, persist_to_global)
- `judgment_rules`: Privilege escalation judgment rule groups (name, enabled, is_active, colors)
- `judgment_rule_conditions`: Rule conditions within groups (target, method, expression, negate, operator, sort_order)
- `scopes`: Request scope patterns for automated privilege testing
- `dedup_configs`: (Global YAML: `~/.burp/repeater_manager/dedup_configs.yaml`)

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
| SnakeYAML | 2.2 | YAML serialization (API extraction rules, judgment rules, user sessions, fields) |
| Apache Commons IO | 2.11.0 | File I/O utilities |
| Apache Commons Lang | 3.12.0 | String/object utilities |
| Apache PDFBox | 3.0.1 | Native PDF report generation with embedded Chinese fonts |
| FreeMarker | 2.3.33 | Template engine for HTML/Markdown report generation |
| CommonMark | 0.22.0 | Markdown-to-HTML rendering for usage tutorial panel |

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
4. **MontoyaApi access**: Prefer constructor injection; use `MontoyaApiHolder.getApi()` as fallback for static contexts (located in `org.oxff.repeater.api` package)
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
15. **FreeMarker templates**: Report templates in `src/main/resources/templates/report/` (*.ftl files); use `FreeMarkerConfig.getConfiguration()` for template loading
16. **Report resources**: Report generation classes in `privilege/report/` follow Template Method pattern with `ReportGenerator` as abstract base; `PdfReportGenerator` requires embedded Chinese font resources
17. **Diff rendering**: Diff components use `DiffEngine` for diff computation and `DiffPane` with `RSyntaxTextArea` for rendering; `SynchronizedScrollPanel` ensures side-by-side scroll sync; `DiffNavigator` provides prev/next change navigation

## CI/CD

GitHub Actions workflow (`.github/workflows/release.yml`):
- **Trigger**: Push `v*` tags (e.g., `v2.34.0`) or manual dispatch
- **Build**: JDK 17 + Maven on Ubuntu
- **Release**: Auto-creates GitHub Release with JAR attachment
- **Prerelease**: Tags with `-` suffix (e.g., `v2.34.0-beta`) are marked as prerelease
