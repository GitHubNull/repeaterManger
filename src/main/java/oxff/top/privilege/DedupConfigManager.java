package oxff.top.privilege;

import burp.BurpExtender;
import burp.api.montoya.http.HttpService;
import oxff.top.privilege.model.DedupConfig;
import oxff.top.privilege.model.DedupKeepPolicy;
import oxff.top.privilege.model.DedupStrategy;

import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * 去重配置管理器（单例）
 * 管理多配置优先级链式匹配，支持双重存储：全局持久化 + 会话级内存
 *
 * 核心逻辑：按优先级遍历所有启用的配置，第一个成功提取到去重键的立即返回；
 * 全部失败则回退到 PATH 策略作为兜底。
 */
public class DedupConfigManager {

    private static DedupConfigManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_CONFIGS_FILE = "dedup_configs.yaml";

    private final String globalConfigsPath;

    /** 全局持久化配置（从YAML加载，线程安全） */
    private final List<DedupConfig> globalConfigs;

    /** 会话级配置（纯内存，线程安全） */
    private final List<DedupConfig> sessionConfigs;

    /** 全局配置的ID计数器 */
    private int globalIdCounter;

    /** 会话配置的ID计数器（使用负数区分） */
    private int sessionIdCounter;

    private DedupConfigManager() {
        String userHome = System.getProperty("user.home");
        this.globalConfigsPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_CONFIGS_FILE;
        this.globalConfigs = new CopyOnWriteArrayList<>();
        this.sessionConfigs = new CopyOnWriteArrayList<>();
        this.globalIdCounter = 0;
        this.sessionIdCounter = -1; // 负数ID区分会话级配置
    }

    /**
     * 获取单例实例
     */
    public static synchronized DedupConfigManager getInstance() {
        if (instance == null) {
            instance = new DedupConfigManager();
        }
        return instance;
    }

    // ==================== 去重核心逻辑 ====================

    /**
     * 计算请求的去重键
     * 按优先级遍历所有启用的配置，第一个成功提取到去重键的立即返回；
     * 全部失败则回退到 PATH 策略。
     *
     * @param requestBytes 请求字节数组
     * @param httpService  HTTP服务信息（可为null）
     * @return 去重键字符串，如果所有策略都失败返回 PATH 策略的结果
     */
    public String computeDedupKey(byte[] requestBytes, HttpService httpService) {
        if (requestBytes == null || requestBytes.length == 0) {
            return ApiDedupEngine.computeDedupKey(requestBytes, httpService, DedupStrategy.PATH, "");
        }

        // 获取所有启用的配置，按优先级升序排列
        List<DedupConfig> activeConfigs = getActiveConfigs();
        if (!activeConfigs.isEmpty()) {
            for (DedupConfig config : activeConfigs) {
                String key = ApiDedupEngine.computeDedupKey(
                        requestBytes, httpService, config.getStrategy(), config.getExpression());
                if (key != null) {
                    return key;
                }
            }
        }

        // 兜底：PATH 策略
        return ApiDedupEngine.computeDedupKey(requestBytes, httpService, DedupStrategy.PATH, "");
    }

    /**
     * 获取当前生效的保留策略
     * 返回最高优先级（priority最小）的启用配置的 keepPolicy
     *
     * @return 保留策略，如果没有活跃配置则返回 FIRST
     */
    public DedupKeepPolicy getKeepPolicy() {
        List<DedupConfig> activeConfigs = getActiveConfigs();
        if (!activeConfigs.isEmpty()) {
            return activeConfigs.get(0).getKeepPolicy();
        }
        return DedupKeepPolicy.FIRST;
    }

    /**
     * 获取所有启用的配置（全局+会话），按优先级升序排列
     */
    public List<DedupConfig> getActiveConfigs() {
        List<DedupConfig> all = new ArrayList<>();
        all.addAll(globalConfigs);
        all.addAll(sessionConfigs);

        return all.stream()
                .filter(DedupConfig::isEnabled)
                .sorted(Comparator.comparingInt(DedupConfig::getPriority))
                .collect(Collectors.toList());
    }

    /**
     * 获取所有配置（含启用和禁用的），按优先级升序排列
     */
    public List<DedupConfig> getAllConfigs() {
        List<DedupConfig> all = new ArrayList<>();
        all.addAll(globalConfigs);
        all.addAll(sessionConfigs);

        all.sort(Comparator.comparingInt(DedupConfig::getPriority));
        return all;
    }

    /**
     * 检查是否有任何启用的配置
     */
    public boolean hasActiveConfigs() {
        return !getActiveConfigs().isEmpty();
    }

    // ==================== 全局配置CRUD ====================

    /**
     * 从磁盘加载全局去重配置
     */
    public void loadGlobalConfigs() {
        List<DedupConfig> loaded = DedupConfigYamlIO.readFromFile(globalConfigsPath);
        globalConfigs.clear();
        globalConfigs.addAll(loaded);

        // 更新ID计数器
        globalIdCounter = loaded.stream()
                .mapToInt(DedupConfig::getId)
                .max()
                .orElse(0);

        BurpExtender.printOutput("[+] 全局去重配置已加载，共 " + globalConfigs.size() + " 条，路径: " + globalConfigsPath);
    }

    /**
     * 保存全局去重配置到磁盘
     */
    public boolean saveGlobalConfigs() {
        boolean result = DedupConfigYamlIO.writeToFile(
                new ArrayList<>(globalConfigs), globalConfigsPath);
        if (result) {
            BurpExtender.printOutput("[+] 全局去重配置已保存，共 " + globalConfigs.size() + " 条");
        }
        return result;
    }

    /**
     * 添加全局配置
     */
    public void addGlobalConfig(DedupConfig config) {
        config.setId(++globalIdCounter);
        config.setStorageType(DedupConfig.StorageType.GLOBAL);
        globalConfigs.add(config);
        saveGlobalConfigs();
        BurpExtender.printOutput("[+] 全局去重配置已添加: " + config.getStrategy().getDisplayName()
                + " (优先级: " + config.getPriority() + ")");
    }

    /**
     * 更新全局配置
     */
    public void updateGlobalConfig(int id, DedupConfig config) {
        for (int i = 0; i < globalConfigs.size(); i++) {
            if (globalConfigs.get(i).getId() == id) {
                config.setId(id);
                config.setStorageType(DedupConfig.StorageType.GLOBAL);
                globalConfigs.set(i, config);
                saveGlobalConfigs();
                BurpExtender.printOutput("[+] 全局去重配置已更新: " + config.getStrategy().getDisplayName()
                        + " (优先级: " + config.getPriority() + ")");
                return;
            }
        }
    }

    /**
     * 删除全局配置
     */
    public void deleteGlobalConfig(int id) {
        globalConfigs.removeIf(c -> c.getId() == id);
        saveGlobalConfigs();
    }

    /**
     * 获取全局配置列表（只读）
     */
    public List<DedupConfig> getGlobalConfigs() {
        return new ArrayList<>(globalConfigs);
    }

    // ==================== 会话配置CRUD（纯内存） ====================

    /**
     * 添加会话级配置
     */
    public void addSessionConfig(DedupConfig config) {
        config.setId(sessionIdCounter--);
        config.setStorageType(DedupConfig.StorageType.SESSION);
        sessionConfigs.add(config);
        BurpExtender.printOutput("[+] 会话级去重配置已添加: " + config.getStrategy().getDisplayName()
                + " (优先级: " + config.getPriority() + ")");
    }

    /**
     * 更新会话级配置
     */
    public void updateSessionConfig(int id, DedupConfig config) {
        for (int i = 0; i < sessionConfigs.size(); i++) {
            if (sessionConfigs.get(i).getId() == id) {
                config.setId(id);
                config.setStorageType(DedupConfig.StorageType.SESSION);
                sessionConfigs.set(i, config);
                return;
            }
        }
    }

    /**
     * 删除会话级配置
     */
    public void deleteSessionConfig(int id) {
        sessionConfigs.removeIf(c -> c.getId() == id);
    }

    /**
     * 清空所有会话级配置
     */
    public void clearSessionConfigs() {
        sessionConfigs.clear();
    }

    /**
     * 获取会话级配置列表（只读）
     */
    public List<DedupConfig> getSessionConfigs() {
        return new ArrayList<>(sessionConfigs);
    }

    // ==================== 通用CRUD ====================

    /**
     * 根据ID删除配置（自动判断全局/会话）
     */
    public void deleteConfig(int id) {
        if (id > 0) {
            deleteGlobalConfig(id);
        } else {
            deleteSessionConfig(id);
        }
    }

    /**
     * 根据ID更新配置（自动判断全局/会话）
     */
    public void updateConfig(int id, DedupConfig config) {
        if (id > 0 || config.getStorageType() == DedupConfig.StorageType.GLOBAL) {
            updateGlobalConfig(id, config);
        } else {
            updateSessionConfig(id, config);
        }
    }

    /**
     * 获取全局配置文件路径
     */
    public String getGlobalConfigsPath() {
        return globalConfigsPath;
    }
}
