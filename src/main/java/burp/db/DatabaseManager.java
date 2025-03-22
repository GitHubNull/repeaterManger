package burp.db;

import burp.BurpExtender;
import burp.config.DatabaseConfig;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.io.File;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 数据库管理类，负责管理数据库连接
 */
public class DatabaseManager {
    private static DatabaseManager instance;
    private final DatabaseConfig dbConfig;
    private HikariDataSource dataSource;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    
    // 私有构造函数，防止直接实例化
    private DatabaseManager() {
        this.dbConfig = new DatabaseConfig();
    }
    
    /**
     * 获取单例实例
     */
    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }
    
    /**
     * 初始化数据库连接池
     */
    public boolean initialize() {
        if (initialized.get()) {
            return true;
        }
        
        try {
            // 确保数据库目录存在
            String dbPath = dbConfig.getDatabasePath();
            File dbFile = new File(dbPath);
            File dbDir = dbFile.getParentFile();
            
            if (!dbDir.exists()) {
                dbDir.mkdirs();
            }
            
            // 配置HikariCP连接池
            HikariConfig config = new HikariConfig();
            config.setJdbcUrl("jdbc:sqlite:" + dbPath);
            config.setDriverClassName("org.sqlite.JDBC");
            
            // 连接池配置
            config.setMaximumPoolSize(5); // SQLite是单线程数据库，所以连接数不需要太多
            config.setMinimumIdle(1);
            config.setIdleTimeout(30000);
            config.setMaxLifetime(60000);
            config.addDataSourceProperty("cachePrepStmts", "true");
            config.addDataSourceProperty("prepStmtCacheSize", "250");
            config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
            config.addDataSourceProperty("useServerPrepStmts", "true");
            
            // 创建数据源
            dataSource = new HikariDataSource(config);
            
            // 初始化表结构
            initializeTables();
            
            initialized.set(true);
            BurpExtender.printOutput("[+] 数据库连接池初始化成功: " + dbPath);
            return true;
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库初始化失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 获取数据库连接
     */
    public Connection getConnection() throws SQLException {
        if (!initialized.get()) {
            initialize();
        }
        
        if (dataSource == null) {
            throw new SQLException("数据库连接池未初始化");
        }
        
        return dataSource.getConnection();
    }
    
    /**
     * 关闭数据库连接池
     */
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            initialized.set(false);
            BurpExtender.printOutput("[+] 数据库连接池已关闭");
        }
    }
    
    /**
     * 初始化表结构
     */
    private void initializeTables() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            
            // 请求表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS requests (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "protocol TEXT, " +
                "domain TEXT, " +
                "path TEXT, " +
                "query TEXT, " +
                "method TEXT, " +
                "add_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "comment TEXT, " +
                "color TEXT, " +
                "request_data BLOB" +
                ")"
            );
            
            // 历史记录表
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS history (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                "request_id INTEGER, " +
                "method TEXT, " +
                "protocol TEXT, " +
                "domain TEXT, " +
                "path TEXT, " +
                "query TEXT, " +
                "status_code INTEGER, " +
                "response_length INTEGER, " +
                "response_time INTEGER, " +
                "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "comment TEXT, " +
                "color TEXT, " +
                "request_data BLOB, " +
                "response_data BLOB, " +
                "FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE" +
                ")"
            );
            
            // 创建索引提升查询性能
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests (domain)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_method ON requests (method)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_request_id ON history (request_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_domain ON history (domain)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_status_code ON history (status_code)");
            
            BurpExtender.printOutput("[+] 数据库表结构初始化成功");
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 初始化表结构失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取配置对象
     */
    public DatabaseConfig getConfig() {
        return dbConfig;
    }
    
    /**
     * 检查数据库状态，包括表是否存在和记录数
     */
    public void checkDatabaseStatus() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            
            BurpExtender.printOutput("[*] 正在检查数据库状态...");
            
            // 检查requests表
            try {
                java.sql.ResultSet rs = stmt.executeQuery("SELECT COUNT(*) AS count FROM requests");
                if (rs.next()) {
                    int count = rs.getInt("count");
                    BurpExtender.printOutput("[+] 请求表(requests)存在，包含 " + count + " 条记录");
                }
                rs.close();
            } catch (SQLException e) {
                BurpExtender.printOutput("[!] 请求表(requests)不存在或查询失败: " + e.getMessage());
            }
            
            // 检查history表
            try {
                java.sql.ResultSet rs = stmt.executeQuery("SELECT COUNT(*) AS count FROM history");
                if (rs.next()) {
                    int count = rs.getInt("count");
                    BurpExtender.printOutput("[+] 历史表(history)存在，包含 " + count + " 条记录");
                }
                rs.close();
            } catch (SQLException e) {
                BurpExtender.printOutput("[!] 历史表(history)不存在或查询失败: " + e.getMessage());
            }
            
            BurpExtender.printOutput("[*] 数据库检查完成，数据库文件路径: " + dbConfig.getDatabasePath());
            
        } catch (SQLException e) {
            BurpExtender.printError("[!] 检查数据库状态失败: " + e.getMessage());
        }
    }
} 