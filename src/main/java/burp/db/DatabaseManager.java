package burp.db;

import burp.BurpExtender;
import burp.config.DatabaseConfig;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.io.File;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
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
     * 获取数据库文件路径
     */
    public String getDatabaseFilePath() {
        return dbConfig.getDatabasePath();
    }
    
    /**
     * 关闭所有数据库连接并重置连接池
     * 用于在导出数据库文件前确保所有连接关闭
     */
    public void closeConnections() {
        if (dataSource != null && !dataSource.isClosed()) {
            BurpExtender.printOutput("[*] 正在关闭所有数据库连接...");
            dataSource.close();
            initialized.set(false);
            BurpExtender.printOutput("[+] 所有数据库连接已关闭");
            
            // 创建一个短暂延迟，确保资源完全释放
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
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
            
            // SQLite配置 - 确保数据持久化
            config.addDataSourceProperty("journal_mode", "DELETE");    // 使用DELETE模式而不是默认的WAL模式
            config.addDataSourceProperty("synchronous", "FULL");       // 使用FULL同步模式确保写入磁盘
            config.addDataSourceProperty("auto_vacuum", "NONE");       // 禁用自动整理
            config.addDataSourceProperty("foreign_keys", "true");      // 启用外键约束
            
            // 创建数据源
            dataSource = new HikariDataSource(config);
            
            // 设置PRAGMA参数以确保数据持久化
            // 注意：我们不能在这里调用getConnection()，因为会导致无限递归
            Connection conn = null;
            Statement stmt = null;
            try {
                // 直接从数据源获取连接，避免调用getConnection()
                conn = dataSource.getConnection();
                stmt = conn.createStatement();
                
                // 设置PRAGMA配置
                stmt.execute("PRAGMA journal_mode=DELETE");  // 使用DELETE日志模式
                stmt.execute("PRAGMA synchronous=FULL");     // 完全同步模式
                stmt.execute("PRAGMA foreign_keys=ON");      // 启用外键
                stmt.execute("PRAGMA auto_vacuum=NONE");     // 禁用自动整理
                BurpExtender.printOutput("[+] 已配置SQLite持久化设置");
                
                // 在这里初始化表结构
                initializeTablesWithConnection(conn);
                
                // 执行VACUUM操作以确保数据库文件正确创建
                stmt.execute("VACUUM");
                BurpExtender.printOutput("[+] 已执行数据库VACUUM操作");
                
            } catch (SQLException e) {
                BurpExtender.printError("[!] 设置SQLite PRAGMA失败: " + e.getMessage());
                // 继续初始化过程而不是退出
            } finally {
                // 关闭资源
                try {
                    if (stmt != null) stmt.close();
                    if (conn != null) conn.close();
                } catch (SQLException e) {
                    BurpExtender.printError("[!] 关闭数据库资源失败: " + e.getMessage());
                }
            }
            
            // 检查数据库文件是否已正确创建
            if (dbFile.exists() && dbFile.length() > 0) {
                BurpExtender.printOutput("[+] 确认数据库文件已创建: " + dbFile.getAbsolutePath() + 
                                     ", 大小: " + dbFile.length() + " 字节");
            } else if (dbFile.exists()) {
                BurpExtender.printOutput("[!] 警告：数据库文件存在但大小为0，可能未正确初始化");
            } else {
                BurpExtender.printOutput("[!] 警告：数据库文件不存在，初始化可能失败");
            }
            
            // 设置初始化完成标志
            initialized.set(true);
            BurpExtender.printOutput("[+] 数据库连接池初始化成功: " + dbPath);
            return true;
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库初始化失败: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 使用现有连接初始化表结构
     */
    private void initializeTablesWithConnection(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            
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
        }
    }
    
    /**
     * 获取数据库连接
     */
    public Connection getConnection() throws SQLException {
        if (!initialized.get()) {
            boolean success = initialize();
            if (!success) {
                throw new SQLException("数据库初始化失败");
            }
        }
        
        if (dataSource == null) {
            throw new SQLException("数据库连接池未初始化");
        }
        
        Connection conn = dataSource.getConnection();
        
        // 确保每个连接都使用正确的SQLite设置
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys=ON");  // 启用外键约束
        } catch (SQLException e) {
            // 忽略错误，不影响主要功能
            BurpExtender.printError("[!] 设置连接PRAGMA失败: " + e.getMessage());
        }
        
        return conn;
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
    
    /**
     * 测试数据库连接并写入测试数据
     * 返回是否成功写入数据
     */
    public boolean testDatabaseWithSampleData() {
        if (!initialized.get()) {
            if (!initialize()) {
                BurpExtender.printError("[!] 数据库初始化失败，无法进行测试");
                return false;
            }
        }
        
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        boolean success = false;
        
        try {
            // 获取连接
            conn = getConnection();
            
            // 关闭自动提交，使用事务
            conn.setAutoCommit(false);
            
            // 添加测试数据
            String insertSQL = "INSERT INTO requests (protocol, domain, path, query, method, request_data) " +
                             "VALUES (?, ?, ?, ?, ?, ?)";
            pstmt = conn.prepareStatement(insertSQL);
            
            pstmt.setString(1, "https");
            pstmt.setString(2, "test.example.com");
            pstmt.setString(3, "/test-path");
            pstmt.setString(4, "param=test");
            pstmt.setString(5, "GET");
            pstmt.setBytes(6, "测试请求数据".getBytes("UTF-8"));
            
            int rows = pstmt.executeUpdate();
            
            // 提交事务
            conn.commit();
            
            BurpExtender.printOutput("[+] 测试数据写入成功：影响 " + rows + " 行");
            
            // 查询测试数据
            PreparedStatement queryStmt = conn.prepareStatement("SELECT COUNT(*) FROM requests");
            rs = queryStmt.executeQuery();
            
            if (rs.next()) {
                int count = rs.getInt(1);
                BurpExtender.printOutput("[+] 确认数据库中有 " + count + " 条请求记录");
                success = (count > 0);
            }
            
            // 检查数据库文件大小
            File dbFile = new File(dbConfig.getDatabasePath());
            if (dbFile.exists()) {
                BurpExtender.printOutput("[+] 数据库文件大小: " + dbFile.length() + " 字节");
                success = success && (dbFile.length() > 0);
            } else {
                BurpExtender.printOutput("[!] 数据库文件不存在");
                success = false;
            }
            
            // 强制执行检查点，确保数据写入磁盘
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("PRAGMA wal_checkpoint(FULL)");
                BurpExtender.printOutput("[+] 执行WAL检查点完成");
            }
            
            return success;
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 测试数据库时出错: " + e.getMessage());
            
            // 回滚事务
            if (conn != null) {
                try {
                    conn.rollback();
                } catch (SQLException ex) {
                    BurpExtender.printError("[!] 回滚事务失败: " + ex.getMessage());
                }
            }
            
            return false;
        } finally {
            // 关闭资源
            try {
                if (rs != null) rs.close();
                if (pstmt != null) pstmt.close();
                if (conn != null) {
                    conn.setAutoCommit(true); // 恢复自动提交
                    conn.close();
                }
            } catch (SQLException e) {
                BurpExtender.printError("[!] 关闭数据库资源失败: " + e.getMessage());
            }
        }
    }
} 