# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enhanced Repeater Manager is a Burp Suite extension that provides advanced HTTP request replay capabilities with persistent storage, history tracking, and enhanced organization features. The plugin is designed for security testers and penetration testers to efficiently manage and organize HTTP/HTTPS requests.

## Architecture

The project follows a layered architecture:
```
+---------------------+
|      UI Layer       |  (Java Swing)
+---------------------+
|   Service Layer     |  (Business logic)
+---------------------+
|   Data Access Layer |  (DAO, Database)
+---------------------+
|   Data Storage      |  (SQLite)
+---------------------+
```

Key components:
- **BurpExtender.java**: Entry point implementing Burp Suite extension interface
- **EnhancedRepeaterUI.java**: Main UI controller that orchestrates all components
- **DatabaseManager.java**: Handles SQLite database connections and initialization
- **RequestResponseRecord.java**: Data model for HTTP requests/responses
- **DAO classes**: Data access objects for requests and history

## Key Features

1. Request Management: Organize and categorize HTTP requests with color marking and comments
2. History Tracking: Automatic recording of request response history for comparison
3. Data Persistence: All requests and history saved to SQLite database
4. Advanced Search: Multi-condition filtering to quickly locate requests/responses
5. Column Display Control: Customizable table columns for better information density
6. Data Import/Export: Support for SQLite and JSON format backup/restore
7. Auto-save: Periodic synchronization of memory data to disk

## Build Commands

To build the project:
```bash
# Using the provided build scripts
./build.sh        # On Linux/macOS
build.bat         # On Windows

# Or using Maven directly
mvn clean package
```

The build process creates two JAR files in the target directory:
- Development version: `target/enhanced-repeater-1.0-SNAPSHOT.jar`
- Timestamped release: `target/releases/enhanced-repeater-1.0-SNAPSHOT-YYYYMMDD-HHMMSS.jar`

## Development Structure

Source code organization:
```
src/main/java/
├── burp/
│   └── BurpExtender.java              # Extension entry point
└── oxff/top/
    ├── config/                        # Configuration management
    │   └── DatabaseConfig.java
    ├── controller/                    # Context menu handlers
    │   └── PopMenu.java
    ├── db/                            # Database access layer
    │   ├── DatabaseManager.java
    │   ├── HistoryDAO.java
    │   └── RequestDAO.java
    ├── http/                          # HTTP processing
    │   ├── RequestManager.java
    │   └── RequestResponseRecord.java
    ├── io/                            # Data import/export
    │   ├── DataExporter.java
    │   └── DataImporter.java
    ├── model/                         # Data models
    ├── service/                       # Background services
    │   └── AutoSaveService.java
    ├── ui/                            # User interface components
    │   ├── BurpRequestPanel.java
    │   ├── BurpResponsePanel.java
    │   ├── ConfigPanel.java
    │   ├── HistoryPanel.java
    │   ├── MainUI.java
    │   ├── RequestListPanel.java
    │   └── RequestPanel.java
    └── utils/                         # Utility classes
```

## Database Schema

Two main tables:
1. `requests`: Stores HTTP request metadata and raw data
2. `history`: Stores request/response history with timing and status information

SQLite is used with HikariCP connection pooling for performance.

## Key Dependencies

- Burp Suite Extender API (v2.1)
- RSyntaxTextArea (v3.3.3) for syntax highlighting
- SQLite JDBC Driver (v3.42.0.0)
- HikariCP (v5.0.1) for connection pooling
- Gson (v2.10.1) for JSON processing
- Apache Commons libraries for utilities

## Configuration

Configuration is stored in `~/.burp/repeater_manager_config.properties` with:
- Database path and filename
- Auto-save settings
- Save interval configuration

Data is persisted in `~/.burp/repeater_manager.db` SQLite database.