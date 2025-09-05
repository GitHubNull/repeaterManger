package oxff.top.db;

import burp.BurpExtender;
import oxff.top.config.DatabaseConfig;
import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
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
    private Connection connection;
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
     * 关闭数据库连接
     */
    public void closeConnections() {
        if (connection != null) {
            try {
                BurpExtender.printOutput("[*] 正在关闭数据库连接...");
                connection.close();
                connection = null;
                initialized.set(false);
                BurpExtender.printOutput("[+] 数据库连接已关闭");
            } catch (SQLException e) {
                BurpExtender.printError("[!] 关闭数据库连接失败: " + e.getMessage());
            }
        }
    }
    
    /**
     * 初始化数据库
     */
    public boolean initialize() {
        if (initialized.get()) {
            BurpExtender.printOutput("[*] 数据库已经初始化，跳过初始化过程");
            return true;
        }
        
        try {
            // 确保数据库目录存在
            String dbPath = dbConfig.getDatabasePath();
            File dbFile = new File(dbPath);
            File dbDir = dbFile.getParentFile();
            
            BurpExtender.printOutput("[*] 数据库文件路径: " + dbPath);
            
            if (!dbDir.exists()) {
                BurpExtender.printOutput("[*] 创建数据库目录: " + dbDir.getAbsolutePath());
                if (!dbDir.mkdirs()) {
                    throw new IOException("无法创建数据库目录: " + dbDir.getAbsolutePath());
                }
            }
            
            // 显式加载SQLite JDBC驱动
            try {
                Class.forName("org.sqlite.JDBC");
                BurpExtender.printOutput("[+] SQLite JDBC驱动加载成功");
            } catch (ClassNotFoundException e) {
                BurpExtender.printError("[!] SQLite JDBC驱动加载失败: " + e.getMessage());
                throw new SQLException("SQLite JDBC驱动未找到", e);
            }
            
            // 使用简单的JDBC连接
            String jdbcUrl = "jdbc:sqlite:" + dbFile.getAbsolutePath().replace("\\", "/");
            BurpExtender.printOutput("[*] JDBC URL: " + jdbcUrl);
            
            // 创建连接
            connection = DriverManager.getConnection(jdbcUrl);
            BurpExtender.printOutput("[+] 数据库连接成功");
            
            // 设置SQLite配置
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA journal_mode=DELETE");
                stmt.execute("PRAGMA synchronous=NORMAL");
                stmt.execute("PRAGMA foreign_keys=ON");
            }
            
            // 初始化数据库表
            if (!dbFile.exists()) {
                BurpExtender.printOutput("[*] 数据库文件不存在，创建新数据库");
                initializeTablesWithConnection(connection);
            } else {
                // 检查表结构
                checkAndUpdateTables(connection);
            }
            
            initialized.set(true);
            BurpExtender.printOutput("[+] 数据库初始化成功");
            return true;
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库初始化失败: " + e.getMessage());
            e.printStackTrace();
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException ex) {
                    BurpExtender.printError("[!] 关闭数据库连接失败: " + ex.getMessage());
                }
                connection = null;
            }
            initialized.set(false);
            return false;
        }
    }
    
    /**
     * 检查并更新表结构
     */
    private void checkAndUpdateTables(Connection conn) throws SQLException {
        try (Statement stmt = conn.createStatement()) {
            // 检查requests表是否存在
            try {
                stmt.executeQuery("SELECT 1 FROM requests LIMIT 1");
            } catch (SQLException e) {
                // 表不存在，创建表
                initializeTablesWithConnection(conn);
                return;
            }
            
            // 检查history表是否存在
            try {
                stmt.executeQuery("SELECT 1 FROM history LIMIT 1");
            } catch (SQLException e) {
                // 表不存在，创建表
                initializeTablesWithConnection(conn);
            }
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
        
        if (connection == null || connection.isClosed()) {
            throw new SQLException("数据库连接未初始化或已关闭");
        }
        
        return connection;
    }
    
    /**
     * 关闭数据库连接
     */
    public void close() {
        closeConnections();
    }
    
    /**
     * 获取配置对象
     */
    public DatabaseConfig getConfig() {
        return dbConfig;
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
     */
    public void testDatabaseWithSampleData() {
        if (!initialized.get()) {
            BurpExtender.printError("[!] 数据库未初始化，无法进行测试");
            return;
        }
        
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // 获取连接
            conn = getConnection();
            conn.setAutoCommit(false); // 开始事务
            
            // 创建测试数据
            stmt = conn.createStatement();
            
            // 先检查是否存在测试数据
            rs = stmt.executeQuery("SELECT COUNT(*) FROM requests WHERE domain = 'test.example.com'");
            if (rs.next() && rs.getInt(1) > 0) {
                // 如果存在测试数据，先删除
                stmt.execute("DELETE FROM requests WHERE domain = 'test.example.com'");
                BurpExtender.printOutput("[*] 已清理旧的测试数据");
            }
            
            // 插入新的测试数据
            String testData = "INSERT INTO requests (protocol, domain, path, query, method, request_data, add_time) " +
                             "VALUES ('http', 'test.example.com', '/', '', 'GET', 'test request', CURRENT_TIMESTAMP)";
            
            int affectedRows = stmt.executeUpdate(testData);
            
            if (affectedRows > 0) {
                BurpExtender.printOutput("[+] 测试数据插入成功");
                conn.commit(); // 提交事务
                
                // 验证数据
                rs = stmt.executeQuery("SELECT COUNT(*) FROM requests");
                if (rs.next()) {
                    BurpExtender.printOutput("[*] 当前请求表记录数: " + rs.getInt(1));
                }
                
                // 删除测试数据
                stmt.execute("DELETE FROM requests WHERE domain = 'test.example.com'");
                conn.commit(); // 提交删除操作
                BurpExtender.printOutput("[+] 测试数据已清理");
                
                BurpExtender.printOutput("[+] 数据库测试完成");
            } else {
                BurpExtender.printError("[!] 测试数据插入失败");
                conn.rollback();
            }
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库测试失败: " + e.getMessage());
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException ex) {
                BurpExtender.printError("[!] 回滚事务失败: " + ex.getMessage());
            }
        } finally {
            // 确保所有资源都被正确关闭
            try {
                if (rs != null) rs.close();
                if (stmt != null) stmt.close();
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