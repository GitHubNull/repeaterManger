package org.oxff.repeater.db;

import burp.BurpExtender;
import org.oxff.repeater.config.DatabaseConfig;
import org.oxff.repeater.db.schema.SchemaInitializer;
import org.oxff.repeater.service.GarbageCollectorService;

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
    private static final int POOL_SIZE = 15;
    private final BlockingQueue<Connection> connectionPool = new ArrayBlockingQueue<>(POOL_SIZE);

    // 当前会话的数据库文件路径
    private String currentDbPath;

    // 垃圾回收服务
    private GarbageCollectorService gcService;


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

            // 停止 GC 服务
            if (gcService != null) {
                gcService.stop();
                gcService = null;
            }

            // 标记正常关闭
            setCleanShutdown(true);

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
     * 重置以开始新会话（生成新的会话目录和数据库文件）
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
            // 清除会话目录状态，下次初始化时将创建新的会话目录
            dbConfig.setSessionDirectory(null);
            BurpExtender.printOutput("[+] 数据库管理器已重置，下次初始化将使用新会话目录");
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

            // 确保会话目录结构完整（含 blobs/、logs/ 子目录）
            org.oxff.repeater.config.SessionDirectory sessionDir = dbConfig.getOrCreateSessionDirectory();
            if (sessionDir != null) {
                sessionDir.ensureCreated();
                BurpExtender.printOutput("[+] 会话目录: " + sessionDir.getAbsolutePath());
            }

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
                stmt.execute("PRAGMA busy_timeout=5000");

                // 委托给SchemaInitializer进行表初始化和迁移
                SchemaInitializer.initializeTablesWithConnection(tempConnection);
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

            // 标记非正常关闭（启动时），正常关闭时在 closeConnections 中设置为 true
            setCleanShutdown(false);

            // 启动垃圾回收服务
            gcService = new GarbageCollectorService();
            gcService.start();

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
            stmt.execute("PRAGMA busy_timeout=5000");
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
     * 设置 clean_shutdown 标记
     */
    private void setCleanShutdown(boolean clean) {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            // 确保 schema_meta 表存在
            stmt.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
            stmt.execute("INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('clean_shutdown', '" + (clean ? "1" : "0") + "')");
        } catch (Exception e) {
            // 忽略，非关键操作
        }
    }

    /**
     * 获取数据库文件所在目录（即会话目录）
     */
    public File getDatabaseParentDirectory() {
        String path = getDatabaseFilePath();
        if (path == null) {
            return null;
        }
        File dbFile = new File(path);
        return dbFile.getParentFile();
    }

    /**
     * 获取当前会话的日志目录
     * 优先使用会话目录下的 logs/，若会话目录不可用则回退到旧默认值
     */
    public File getLogsDirectory() {
        return dbConfig.getLogsDirectory();
    }

    /**
     * 获取 GC 服务实例
     */
    public GarbageCollectorService getGcService() {
        return gcService;
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
