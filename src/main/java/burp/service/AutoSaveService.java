package burp.service;

import burp.BurpExtender;
import burp.config.DatabaseConfig;
import burp.db.DatabaseManager;
import burp.ui.MainUI;
import burp.db.RequestDAO;
import burp.db.HistoryDAO;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 自动保存服务 - 定期将数据持久化到数据库
 */
public class AutoSaveService {
    private final DatabaseManager dbManager;
    private ScheduledExecutorService scheduler;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private MainUI mainUI;
    private int lastRequestCount = 0;
    private int lastHistoryCount = 0;
    
    /**
     * 创建自动保存服务
     */
    public AutoSaveService() {
        this.dbManager = DatabaseManager.getInstance();
    }
    
    /**
     * 创建自动保存服务（指定DAO对象）
     * 用于刷新数据时创建临时实例
     */
    public AutoSaveService(RequestDAO requestDAO, HistoryDAO historyDAO) {
        this.dbManager = DatabaseManager.getInstance();
        // DAO对象只在performSave方法中使用，因此此构造函数仅用于创建不会执行保存操作的临时实例
    }
    
    /**
     * 设置主UI引用
     */
    public void setMainUI(MainUI mainUI) {
        this.mainUI = mainUI;
    }
    
    /**
     * 启动自动保存服务
     */
    public void start() {
        if (running.get()) {
            return; // 已经在运行中
        }
        
        DatabaseConfig config = dbManager.getConfig();
        if (!config.isAutoSaveEnabled()) {
            BurpExtender.printOutput("[*] 自动保存功能已禁用");
            return;
        }
        
        int intervalMinutes = config.getAutoSaveInterval();
        if (intervalMinutes <= 0) {
            intervalMinutes = 5; // 默认5分钟
        }
        
        BurpExtender.printOutput("[+] 启动自动保存服务，间隔: " + intervalMinutes + "分钟");
        
        // 关闭已存在的调度器
        stop();
        
        // 创建新的调度器
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(
            this::performSave,
            intervalMinutes,
            intervalMinutes,
            TimeUnit.MINUTES
        );
        
        running.set(true);
        
        // 记录当前数据状态
        if (mainUI != null) {
            lastRequestCount = mainUI.getRequestListPanel().getRequestCount();
            lastHistoryCount = mainUI.getHistoryPanel().getHistoryCount();
            BurpExtender.printOutput("[*] 初始数据状态: 请求数 " + lastRequestCount + 
                                  ", 历史记录数 " + lastHistoryCount);
        }
    }
    
    /**
     * 停止自动保存服务
     */
    public void stop() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        running.set(false);
        BurpExtender.printOutput("[*] 自动保存服务已停止");
    }
    
    /**
     * 执行保存操作
     */
    private void performSave() {
        try {
            BurpExtender.printOutput("[*] 执行自动保存操作...");
            
            // 确保数据库已初始化
            if (!dbManager.initialize()) {
                BurpExtender.printError("[!] 数据库初始化失败，无法执行自动保存");
                return;
            }
            
            // 检查是否有新数据
            int currentRequestCount = 0;
            int currentHistoryCount = 0;
            
            if (mainUI != null) {
                currentRequestCount = mainUI.getRequestListPanel().getRequestCount();
                currentHistoryCount = mainUI.getHistoryPanel().getHistoryCount();
                
                BurpExtender.printOutput("[*] 当前数据状态: 请求数 " + currentRequestCount + 
                                     ", 历史记录数 " + currentHistoryCount);
                
                boolean hasNewData = currentRequestCount > lastRequestCount || 
                                  currentHistoryCount > lastHistoryCount;
                
                if (hasNewData) {
                    BurpExtender.printOutput("[+] 检测到新数据，需要保存");
                } else {
                    BurpExtender.printOutput("[*] 未检测到新数据");
                }
                
                // 更新上次记录的计数
                lastRequestCount = currentRequestCount;
                lastHistoryCount = currentHistoryCount;
            }
            
            // 检查数据库状态
            dbManager.checkDatabaseStatus();
            
            // 实际的保存操作由数据库管理器负责
            // 这里由于我们使用的是SQLite，数据实时保存，所以不需要额外的保存操作
            // 如果需要，可以在这里添加任何清理或优化操作
            
            // 执行WAL检查点，确保数据已写入主数据库文件
            try (java.sql.Connection conn = dbManager.getConnection();
                 java.sql.Statement stmt = conn.createStatement()) {
                // 执行检查点操作
                stmt.execute("PRAGMA wal_checkpoint(FULL)");
                BurpExtender.printOutput("[+] 已执行数据库检查点操作，确保数据已持久化");
            } catch (java.sql.SQLException e) {
                BurpExtender.printError("[!] 执行数据库检查点时出错: " + e.getMessage());
            }
            
            BurpExtender.printOutput("[+] 自动保存完成");
            
        } catch (Exception e) {
            BurpExtender.printError("[!] 执行自动保存时出错: " + e.getMessage());
        }
    }
    
    /**
     * 手动触发保存操作
     */
    public void saveNow() {
        new Thread(this::performSave).start();
    }
    
    /**
     * 检查服务是否正在运行
     */
    public boolean isRunning() {
        return running.get();
    }
} 