package org.oxff.repeater.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

import burp.BurpExtender;

/**
 * 数据库配置管理类 - 支持三种存储模式：自动、指定目录、指定文件
 */
public class DatabaseConfig {
    private static final String CONFIG_FILE = "repeater_manager_config.properties";

    private Properties properties;
    private File configFile;

    // 配置属性键名
    public static final String KEY_STORAGE_MODE = "storage.mode";
    public static final String KEY_STORAGE_BASE_DIR = "storage.base_dir";
    public static final String KEY_AUTO_SAVE = "auto.save";
    public static final String KEY_SAVE_INTERVAL = "save.interval";

    // 日志配置键
    public static final String KEY_LOG_LEVEL = "log.level";
    public static final String KEY_LOG_FILE_ENABLED = "log.file.enabled";
    public static final String KEY_LOG_FILE_DIRECTORY = "log.file.directory";
    public static final String KEY_LOG_FILE_MAX_SIZE = "log.file.max_size";
    public static final String KEY_LOG_FILE_MAX_BACKUPS = "log.file.max_backups";
    public static final String KEY_LOG_UI_ENABLED = "log.ui.enabled";
    public static final String KEY_LOG_UI_MAX_ENTRIES = "log.ui.max_entries";
    public static final String KEY_LOG_BURP_CONSOLE_ENABLED = "log.burp_console.enabled";

    // 代理配置键
    public static final String KEY_PROXY_ENABLED = "proxy.enabled";
    public static final String KEY_PROXY_HOST = "proxy.host";
    public static final String KEY_PROXY_PORT = "proxy.port";

    // API提取规则配置键
    public static final String KEY_API_EXTRACTION_RULES = "api.extraction.rules";

    // 旧版配置键（用于迁移）
    private static final String OLD_KEY_DB_PATH = "db.path";
    private static final String OLD_KEY_DB_FILENAME = "db.filename";

    // 存储模式
    public static final String MODE_AUTO = "auto";
    public static final String MODE_DIRECTORY = "directory";
    public static final String MODE_FILE = "file";

    // 当前会话文件名（不持久化，FILE 模式使用）
    private String sessionFile;

    // 当前会话目录（不持久化，AUTO/DIRECTORY 模式使用）
    private SessionDirectory sessionDirectory;

    /**
     * 初始化数据库配置
     */
    public DatabaseConfig() {
        properties = new Properties();

        // 获取用户主目录下的.burp目录
        String userHome = System.getProperty("user.home");
        File burpDir = new File(userHome, ".burp");

        // 确保burp配置目录存在
        if (!burpDir.exists()) {
            burpDir.mkdirs();
        }

        // 配置文件路径
        configFile = new File(burpDir, CONFIG_FILE);

        // 如果配置文件存在，加载它
        if (configFile.exists()) {
            try (FileInputStream fis = new FileInputStream(configFile)) {
                properties.load(fis);
                BurpExtender.printOutput("[+] 已加载配置文件：" + configFile.getAbsolutePath());
                migrateOldConfig();
            } catch (IOException e) {
                BurpExtender.printError("[!] 加载配置文件失败: " + e.getMessage());
                setDefaultConfig();
            }
        } else {
            // 创建默认配置
            setDefaultConfig();
            saveConfig();
        }
    }

    /**
     * 从旧版配置迁移
     */
    private void migrateOldConfig() {
        // 如果存在旧版配置但没有新版配置，进行迁移
        if (properties.containsKey(OLD_KEY_DB_PATH) && !properties.containsKey(KEY_STORAGE_MODE)) {
            String oldPath = properties.getProperty(OLD_KEY_DB_PATH, "");
            String oldFilename = properties.getProperty(OLD_KEY_DB_FILENAME, "");
            if (!oldPath.isEmpty() && !oldFilename.isEmpty()) {
                properties.setProperty(KEY_STORAGE_MODE, MODE_DIRECTORY);
                properties.setProperty(KEY_STORAGE_BASE_DIR, oldPath);
                BurpExtender.printOutput("[*] 已从旧版配置迁移到新版存储配置");
            }
            // 移除旧版键
            properties.remove(OLD_KEY_DB_PATH);
            properties.remove(OLD_KEY_DB_FILENAME);
            saveConfig();
        }
    }

    /**
     * 设置默认配置
     */
    private void setDefaultConfig() {
        properties.setProperty(KEY_STORAGE_MODE, MODE_AUTO);
        properties.setProperty(KEY_STORAGE_BASE_DIR, "");
        properties.setProperty(KEY_AUTO_SAVE, "true");
        properties.setProperty(KEY_SAVE_INTERVAL, "5"); // 5分钟

        // 日志默认配置
        properties.setProperty(KEY_LOG_LEVEL, "INFO");
        properties.setProperty(KEY_LOG_FILE_ENABLED, "true");
        properties.setProperty(KEY_LOG_FILE_DIRECTORY, "");
        properties.setProperty(KEY_LOG_FILE_MAX_SIZE, "5242880"); // 5MB
        properties.setProperty(KEY_LOG_FILE_MAX_BACKUPS, "5");
        properties.setProperty(KEY_LOG_UI_ENABLED, "true");
        properties.setProperty(KEY_LOG_UI_MAX_ENTRIES, "128");
        properties.setProperty(KEY_LOG_BURP_CONSOLE_ENABLED, "true");

        // 代理默认配置
        properties.setProperty(KEY_PROXY_ENABLED, "false");
        properties.setProperty(KEY_PROXY_HOST, "127.0.0.1");
        properties.setProperty(KEY_PROXY_PORT, "8080");

        BurpExtender.printOutput("[+] 已使用默认配置（自动模式）");
    }

    /**
     * 保存配置到文件
     */
    public boolean saveConfig() {
        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            properties.store(fos, "Repeater Manager Configuration");
            BurpExtender.printOutput("[+] 已保存配置到：" + configFile.getAbsolutePath());
            return true;
        } catch (IOException e) {
            BurpExtender.printError("[!] 保存配置文件失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 生成会话目录名称
     * 格式: repeater_manager_YYYY_MMDD_HHmm_ssSSS
     * 与原数据库文件名格式一致（去掉 .sqlite3 后缀）
     */
    public static String generateSessionDirectoryName() {
        return SessionDirectory.generateSessionDirectoryName();
    }

    /**
     * 生成数据库文件名
     * 格式: repeater_manager_YYYY_MMDD_HHmm_ssSSS.sqlite3
     * @deprecated 使用 {@link #generateSessionDirectoryName()} 代替，会话目录模式下数据库文件名为固定名称
     */
    @Deprecated
    public static String generateDatabaseFilename() {
        return generateSessionDirectoryName() + ".sqlite3";
    }

    /**
     * 获取默认基础目录（Burp启动目录下的repeater_manager）
     */
    public static String getDefaultBaseDirectory() {
        String userDir = System.getProperty("user.dir");
        File repeaterDir = new File(userDir, "repeater_manager");
        return repeaterDir.getAbsolutePath();
    }

    /**
     * 获取有效的数据库路径（根据当前模式解析）
     * AUTO/DIRECTORY 模式下返回会话目录内的固定名称数据库文件
     * FILE 模式下返回用户指定的文件路径
     */
    public String getEffectiveDatabasePath() {
        // 1. 如果设置了当前会话文件名（FILE 模式），直接使用
        if (sessionFile != null && !sessionFile.isEmpty()) {
            return sessionFile;
        }

        // 2. 如果已有会话目录，返回其中的数据库文件
        if (sessionDirectory != null) {
            return sessionDirectory.getDatabaseFile().getAbsolutePath();
        }

        // 3. 根据存储模式创建新的会话目录
        String baseDir;
        String mode = getStorageMode();

        if (MODE_DIRECTORY.equals(mode)) {
            baseDir = getBaseDirectory();
            if (baseDir == null || baseDir.isEmpty()) {
                baseDir = getDefaultBaseDirectory();
            }
        } else {
            // auto 模式或其他
            baseDir = getDefaultBaseDirectory();
        }

        // 确保基础目录存在
        File dir = new File(baseDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        // 创建新的时间戳会话目录
        sessionDirectory = SessionDirectory.createNew(baseDir);
        return sessionDirectory.getDatabaseFile().getAbsolutePath();
    }

    /**
     * 获取存储模式
     */
    public String getStorageMode() {
        return properties.getProperty(KEY_STORAGE_MODE, MODE_AUTO);
    }

    /**
     * 设置存储模式
     */
    public void setStorageMode(String mode) {
        properties.setProperty(KEY_STORAGE_MODE, mode);
    }

    /**
     * 获取基础目录
     */
    public String getBaseDirectory() {
        return properties.getProperty(KEY_STORAGE_BASE_DIR, "");
    }

    /**
     * 设置基础目录
     */
    public void setBaseDirectory(String baseDir) {
        properties.setProperty(KEY_STORAGE_BASE_DIR, baseDir);
    }

    /**
     * 获取当前会话文件名（不持久化）
     */
    public String getSessionFile() {
        return sessionFile;
    }

    /**
     * 设置当前会话文件名（不持久化）
     */
    public void setSessionFile(String sessionFile) {
        this.sessionFile = sessionFile;
    }

    /**
     * 获取或创建当前会话目录
     * 如果尚未创建会话目录，则根据当前模式创建一个新的
     *
     * @return 当前会话目录，FILE 模式下返回 null
     */
    public SessionDirectory getOrCreateSessionDirectory() {
        if (sessionDirectory != null) {
            return sessionDirectory;
        }

        // FILE 模式：从 sessionFile 路径推断会话目录（DB 文件的父目录）
        if (sessionFile != null && !sessionFile.isEmpty()) {
            File dbFile = new File(sessionFile);
            sessionDirectory = new SessionDirectory(dbFile.getParentFile());
            return sessionDirectory;
        }

        // AUTO/DIRECTORY 模式：调用 getEffectiveDatabasePath() 会创建会话目录
        getEffectiveDatabasePath();
        return sessionDirectory;
    }

    /**
     * 设置会话目录（不持久化）
     * 用于会话切换时设置新的会话目录
     */
    public void setSessionDirectory(SessionDirectory dir) {
        this.sessionDirectory = dir;
    }

    /**
     * 获取日志目录
     * 优先使用会话目录下的 logs/，若会话目录不可用则回退到旧默认值
     *
     * @return 日志目录的 File 对象
     */
    public File getLogsDirectory() {
        if (sessionDirectory != null) {
            return sessionDirectory.getLogsDir();
        }
        // 回退：旧默认值
        return new File(getDefaultBaseDirectory(), "logs");
    }

    /**
     * 获取数据库文件路径（兼容旧版调用）
     */
    public String getDatabasePath() {
        return getEffectiveDatabasePath();
    }

    /**
     * 设置数据库路径（兼容旧版调用，转为目录模式）
     */
    public void setDatabasePath(String path) {
        File file = new File(path);
        setStorageMode(MODE_DIRECTORY);
        setBaseDirectory(file.getParent());
        saveConfig();
    }

    /**
     * 获取自定义属性值
     */
    public String getProperty(String key, String defaultValue) {
        return properties.getProperty(key, defaultValue);
    }

    /**
     * 设置自定义属性值
     */
    public void setProperty(String key, String value) {
        properties.setProperty(key, value);
    }

    /**
     * 判断是否启用自动保存
     */
    public boolean isAutoSaveEnabled() {
        return Boolean.parseBoolean(properties.getProperty(KEY_AUTO_SAVE, "true"));
    }

    /**
     * 获取自动保存间隔（分钟）
     */
    public int getAutoSaveInterval() {
        try {
            return Integer.parseInt(properties.getProperty(KEY_SAVE_INTERVAL, "5"));
        } catch (NumberFormatException e) {
            return 5; // 默认5分钟
        }
    }

    // ========== 日志配置便捷方法 ==========

    public String getLogLevel() {
        return properties.getProperty(KEY_LOG_LEVEL, "INFO");
    }

    public void setLogLevel(String level) {
        properties.setProperty(KEY_LOG_LEVEL, level);
    }

    public boolean isLogFileEnabled() {
        return Boolean.parseBoolean(properties.getProperty(KEY_LOG_FILE_ENABLED, "true"));
    }

    public void setLogFileEnabled(boolean enabled) {
        properties.setProperty(KEY_LOG_FILE_ENABLED, String.valueOf(enabled));
    }

    public String getLogFileDirectory() {
        return properties.getProperty(KEY_LOG_FILE_DIRECTORY, "");
    }

    public void setLogFileDirectory(String directory) {
        properties.setProperty(KEY_LOG_FILE_DIRECTORY, directory);
    }

    public long getLogFileMaxSize() {
        try {
            return Long.parseLong(properties.getProperty(KEY_LOG_FILE_MAX_SIZE, "5242880"));
        } catch (NumberFormatException e) {
            return 5242880; // 默认5MB
        }
    }

    public void setLogFileMaxSize(long maxSize) {
        properties.setProperty(KEY_LOG_FILE_MAX_SIZE, String.valueOf(maxSize));
    }

    public int getLogFileMaxBackups() {
        try {
            return Integer.parseInt(properties.getProperty(KEY_LOG_FILE_MAX_BACKUPS, "5"));
        } catch (NumberFormatException e) {
            return 5;
        }
    }

    public void setLogFileMaxBackups(int maxBackups) {
        properties.setProperty(KEY_LOG_FILE_MAX_BACKUPS, String.valueOf(maxBackups));
    }

    public boolean isLogUIEnabled() {
        return Boolean.parseBoolean(properties.getProperty(KEY_LOG_UI_ENABLED, "true"));
    }

    public void setLogUIEnabled(boolean enabled) {
        properties.setProperty(KEY_LOG_UI_ENABLED, String.valueOf(enabled));
    }

    public int getLogUIMaxEntries() {
        try {
            return Integer.parseInt(properties.getProperty(KEY_LOG_UI_MAX_ENTRIES, "128"));
        } catch (NumberFormatException e) {
            return 128;
        }
    }

    public void setLogUIMaxEntries(int maxEntries) {
        properties.setProperty(KEY_LOG_UI_MAX_ENTRIES, String.valueOf(maxEntries));
    }

    public boolean isLogBurpConsoleEnabled() {
        return Boolean.parseBoolean(properties.getProperty(KEY_LOG_BURP_CONSOLE_ENABLED, "true"));
    }

    public void setLogBurpConsoleEnabled(boolean enabled) {
        properties.setProperty(KEY_LOG_BURP_CONSOLE_ENABLED, String.valueOf(enabled));
    }

    // ========== 代理配置便捷方法 ==========

    public boolean isProxyEnabled() {
        return Boolean.parseBoolean(properties.getProperty(KEY_PROXY_ENABLED, "false"));
    }

    public void setProxyEnabled(boolean enabled) {
        properties.setProperty(KEY_PROXY_ENABLED, String.valueOf(enabled));
    }

    public String getProxyHost() {
        return properties.getProperty(KEY_PROXY_HOST, "127.0.0.1");
    }

    public void setProxyHost(String host) {
        properties.setProperty(KEY_PROXY_HOST, host);
    }

    public int getProxyPort() {
        try {
            return Integer.parseInt(properties.getProperty(KEY_PROXY_PORT, "8080"));
        } catch (NumberFormatException e) {
            return 8080;
        }
    }

    public void setProxyPort(int port) {
        properties.setProperty(KEY_PROXY_PORT, String.valueOf(port));
    }
}
