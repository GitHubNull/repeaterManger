package oxff.top.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;

import burp.BurpExtender;

/**
 * 数据库配置管理类
 */
public class DatabaseConfig {
    private static final String CONFIG_FILE = "repeater_manager_config.properties";
    private static final String DEFAULT_DB_NAME = "repeater_manager.db";
    
    private Properties properties;
    private File configFile;
    
    // 配置属性键名
    public static final String KEY_DB_PATH = "db.path";
    public static final String KEY_DB_FILENAME = "db.filename";
    public static final String KEY_AUTO_SAVE = "auto.save";
    public static final String KEY_SAVE_INTERVAL = "save.interval";
    
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
            } catch (IOException e) {
                BurpExtender.printError("[!] 加载配置文件失败: " + e.getMessage());
                // 使用默认配置
                setDefaultConfig();
            }
        } else {
            // 创建默认配置
            setDefaultConfig();
            saveConfig();
        }
    }
    
    /**
     * 设置默认配置
     */
    private void setDefaultConfig() {
        String userHome = System.getProperty("user.home");
        File burpDir = new File(userHome, ".burp");
        
        properties.setProperty(KEY_DB_PATH, burpDir.getAbsolutePath());
        properties.setProperty(KEY_DB_FILENAME, DEFAULT_DB_NAME);
        properties.setProperty(KEY_AUTO_SAVE, "true");
        properties.setProperty(KEY_SAVE_INTERVAL, "5"); // 5分钟
        
        BurpExtender.printOutput("[+] 已使用默认配置");
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
     * 获取数据库文件路径
     */
    public String getDatabasePath() {
        String dbPath = properties.getProperty(KEY_DB_PATH);
        String dbFilename = properties.getProperty(KEY_DB_FILENAME);
        return Paths.get(dbPath, dbFilename).toString();
    }
    
    /**
     * 设置数据库路径
     */
    public void setDatabasePath(String path) {
        File file = new File(path);
        properties.setProperty(KEY_DB_PATH, file.getParent());
        properties.setProperty(KEY_DB_FILENAME, file.getName());
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
} 