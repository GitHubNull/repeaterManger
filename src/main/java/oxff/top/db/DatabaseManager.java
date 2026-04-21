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
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * 数据库管理类，负责管理数据库连接
 * 使用连接池复用连接，避免频繁创建/销毁连接的开销
 */
public class DatabaseManager {
    private static DatabaseManager instance;
    private final DatabaseConfig dbConfig;
    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final Object connectionLock = new Object();

    // 连接池：复用数据库连接，避免每次请求都新建连接
    private static final int POOL_SIZE = 5;
    private final BlockingQueue<Connection> connectionPool = new ArrayBlockingQueue<>(POOL_SIZE);

    // 当前会话的数据库文件路径
    private String currentDbPath;

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
     * 获取当前数据库文件路径
     */
    public String getDatabaseFilePath() {
        return currentDbPath != null ? currentDbPath : dbConfig.getEffectiveDatabasePath();
    }

    /**
     * 获取当前数据库文件路径（别名）
     */
    public String getCurrentDatabasePath() {
        return currentDbPath;
    }

    /**
     * 关闭数据库连接管理器
     */
    public void closeConnections() {
        synchronized (connectionLock) {
            BurpExtender.printOutput("[*] 正在关闭数据库连接管理器...");
            // 关闭连接池中的所有连接
            Connection conn;
            while ((conn = connectionPool.poll()) != null) {
                try {
                    if (!conn.isClosed()) {
                        conn.close();
                    }
                } catch (SQLException e) {
                    // 忽略关闭错误
                }
            }
            initialized.set(false);
            BurpExtender.printOutput("[+] 数据库连接管理器已关闭");
        }
    }

    /**
     * 重置以开始新会话（生成新的数据库文件）
     */
    public void resetForNewSession() {
        synchronized (connectionLock) {
            BurpExtender.printOutput("[*] 重置数据库管理器以开始新会话...");
            // 先关闭现有连接池中的连接
            Connection conn;
            while ((conn = connectionPool.poll()) != null) {
                try {
                    if (!conn.isClosed()) {
                        conn.close();
                    }
                } catch (SQLException e) {
                    // 忽略关闭错误
                }
            }
            initialized.set(false);
            currentDbPath = null;
            BurpExtender.printOutput("[+] 数据库管理器已重置，下次初始化将使用新数据库文件");
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
            // 解析当前会话的数据库路径
            currentDbPath = dbConfig.getEffectiveDatabasePath();
            File dbFile = new File(currentDbPath);
            File dbDir = dbFile.getParentFile();

            BurpExtender.printOutput("[*] 数据库文件路径: " + currentDbPath);

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

            // 创建临时连接用于初始化
            try (Connection tempConnection = DriverManager.getConnection(jdbcUrl);
                 Statement stmt = tempConnection.createStatement()) {

                BurpExtender.printOutput("[+] 数据库连接成功");

                // 设置SQLite配置
                stmt.execute("PRAGMA journal_mode=DELETE");
                stmt.execute("PRAGMA synchronous=NORMAL");
                stmt.execute("PRAGMA foreign_keys=ON");

                // 每次初始化都是新文件，直接创建表
                initializeTablesWithConnection(tempConnection);
            }

            // 预填充连接池
            connectionPool.clear();
            for (int i = 0; i < POOL_SIZE; i++) {
                Connection poolConn = createNewConnection();
                if (poolConn != null) {
                    connectionPool.offer(poolConn);
                }
            }
            BurpExtender.printOutput("[+] 数据库连接池已创建，大小: " + connectionPool.size());

            initialized.set(true);
            BurpExtender.printOutput("[+] 数据库初始化成功: " + currentDbPath);
            return true;
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库初始化失败: " + e.getMessage());
            e.printStackTrace();
            initialized.set(false);
            currentDbPath = null;
            return false;
        }
    }

    /**
     * 创建新的数据库连接（内部方法）
     */
    private Connection createNewConnection() throws SQLException {
        File dbFile = new File(currentDbPath);
        String jdbcUrl = "jdbc:sqlite:" + dbFile.getAbsolutePath().replace("\\", "/");
        Connection conn = DriverManager.getConnection(jdbcUrl);

        // 设置SQLite配置（仅在连接创建时执行一次）
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA journal_mode=DELETE");
            stmt.execute("PRAGMA synchronous=NORMAL");
            stmt.execute("PRAGMA foreign_keys=ON");
        }

        return conn;
    }

    /**
     * 获取数据库连接（从连接池获取，返回代理连接）
     * 返回的Connection代理在调用close()时会自动归还到连接池，
     * 因此现有使用try-with-resources的代码无需修改。
     */
    public Connection getConnection() throws SQLException {
        if (!initialized.get()) {
            synchronized (this) {
                if (!initialized.get()) {
                    boolean success = initialize();
                    if (!success) {
                        throw new SQLException("数据库初始化失败");
                    }
                }
            }
        }

        try {
            // 从连接池获取连接（最多等待2秒）
            Connection conn = connectionPool.poll(2, java.util.concurrent.TimeUnit.SECONDS);
            if (conn == null || conn.isClosed()) {
                // 如果池中连接不可用，创建新连接
                conn = createNewConnection();
            }
            // 返回代理连接，close()时自动归还到池中
            return createPooledConnectionProxy(conn);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            // 中断时直接创建新连接
            return createPooledConnectionProxy(createNewConnection());
        } catch (Exception e) {
            BurpExtender.printError("[!] 获取数据库连接失败: " + e.getMessage());
            throw new SQLException("获取数据库连接失败: " + e.getMessage());
        }
    }

    /**
     * 创建连接池代理：拦截close()调用，将连接归还到池中而非真正关闭
     * 这样现有的try-with-resources代码无需修改即可自动复用连接
     */
    private Connection createPooledConnectionProxy(Connection realConnection) {
        return (Connection) Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class[]{Connection.class},
            new PooledConnectionInvocationHandler(realConnection)
        );
    }

    /**
     * 连接池代理的调用处理器
     * 拦截close()方法，将连接归还到池中
     */
    private class PooledConnectionInvocationHandler implements InvocationHandler {
        private final Connection realConnection;
        private boolean closed = false;

        PooledConnectionInvocationHandler(Connection realConnection) {
            this.realConnection = realConnection;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // 拦截close()方法，归还连接到池中
            if ("close".equals(method.getName())) {
                if (!closed) {
                    closed = true;
                    // 确保连接处于自动提交模式（SQLite默认）
                    try {
                        if (!realConnection.getAutoCommit()) {
                            realConnection.setAutoCommit(true);
                        }
                    } catch (SQLException e) {
                        // 忽略
                    }
                    // 归还到连接池
                    if (!realConnection.isClosed()) {
                        if (!connectionPool.offer(realConnection)) {
                            // 池已满，真正关闭连接
                            realConnection.close();
                        }
                    }
                }
                return null;
            }

            // 拦截isClosed()方法，返回代理的关闭状态
            if ("isClosed".equals(method.getName())) {
                return closed || realConnection.isClosed();
            }

            // 如果代理已关闭，除close/isClosed外的方法都抛异常
            if (closed) {
                throw new SQLException("Connection is closed");
            }

            // 其他方法委托给真实连接
            return method.invoke(realConnection, args);
        }
    }

    /**
     * 归还数据库连接到连接池
     * @deprecated 使用连接代理后无需手动调用，close()会自动归还
     */
    @Deprecated
    public void returnConnection(Connection conn) {
        if (conn == null) return;
        try {
            // 如果是代理连接，直接close即可归还
            if (Proxy.isProxyClass(conn.getClass())) {
                conn.close();
                return;
            }
            // 原始连接直接归还到池
            if (!conn.isClosed()) {
                if (!connectionPool.offer(conn)) {
                    conn.close();
                }
            }
        } catch (SQLException e) {
            BurpExtender.printError("[!] 归还数据库连接失败: " + e.getMessage());
        }
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
     * 检查数据库连接是否可用
     */
    public boolean isConnectionValid() {
        if (!initialized.get()) {
            return false;
        }

        try (Connection conn = getConnection()) {
            return conn != null && conn.isValid(2); // 缩短超时时间
        } catch (Exception e) {
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
                "request_id INTEGER, " +  // Allow NULL for unsaved requests
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
                "FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE SET NULL" +  // Changed from CASCADE to SET NULL
                ")"
            );

            // 创建索引提升查询性能
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_domain ON requests (domain)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_requests_method ON requests (method)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_request_id ON history (request_id)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_domain ON history (domain)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_history_status_code ON history (status_code)");

            // 修复AUTOINCREMENT序列：如果requests表为空，重置序列计数器
            // 这是为了修复之前testDatabaseWithSampleData插入测试数据消耗ID的问题
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM requests")) {
                if (rs.next() && rs.getInt(1) == 0) {
                    // 表为空时，删除sqlite_sequence中的记录，使ID从1重新开始
                    stmt.execute("DELETE FROM sqlite_sequence WHERE name = 'requests'");
                    BurpExtender.printOutput("[*] requests表为空，已重置AUTOINCREMENT序列");
                }
            }

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

            BurpExtender.printOutput("[*] 数据库检查完成，数据库文件路径: " + currentDbPath);

        } catch (SQLException e) {
            BurpExtender.printError("[!] 检查数据库状态失败: " + e.getMessage());
        }
    }

    /**
     * 测试数据库连接是否正常
     * 注意：不再向requests表插入测试数据，避免消耗AUTOINCREMENT的ID序列，
     * 导致用户实际请求的编号不从1开始。
     */
    public void testDatabaseWithSampleData() {
        if (!initialized.get()) {
            BurpExtender.printError("[!] 数据库未初始化，无法进行测试");
            return;
        }

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            // 使用简单查询验证数据库连接和表结构，不写入任何数据
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM requests")) {
                if (rs.next()) {
                    BurpExtender.printOutput("[*] 当前请求表记录数: " + rs.getInt(1));
                }
            }

            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM history")) {
                if (rs.next()) {
                    BurpExtender.printOutput("[*] 当前历史记录表记录数: " + rs.getInt(1));
                }
            }

            BurpExtender.printOutput("[+] 数据库连接测试完成");
        } catch (Exception e) {
            BurpExtender.printError("[!] 数据库测试失败: " + e.getMessage());
        }
    }
}
