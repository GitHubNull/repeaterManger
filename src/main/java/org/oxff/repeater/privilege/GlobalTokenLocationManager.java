package org.oxff.repeater.privilege;

import burp.BurpExtender;
import org.oxff.repeater.privilege.model.TokenLocation;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 全局令牌位置管理器（单例）
 * 管理保存在 ~/.burp/repeater_manager/token_locations.yaml 中的全局令牌位置
 * 全局令牌位置可被任何新项目自动加载
 */
public class GlobalTokenLocationManager {
    private static GlobalTokenLocationManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_LOCATIONS_FILE = "token_locations.yaml";

    private final String globalLocationsPath;
    private List<TokenLocation> globalLocations;
    private GlobalTokenLocationManager() {
        String userHome = System.getProperty("user.home");
        this.globalLocationsPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_LOCATIONS_FILE;
        this.globalLocations = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalTokenLocationManager getInstance() {
        if (instance == null) {
            instance = new GlobalTokenLocationManager();
        }
        return instance;
    }

    /**
     * 获取全局令牌位置文件路径
     */
    public String getGlobalLocationsPath() {
        return globalLocationsPath;
    }

    /**
     * 从磁盘加载全局令牌位置
     */
    public void loadLocations() {
        globalLocations = TokenLocationYamlIO.readFromFile(globalLocationsPath);
        BurpExtender.printOutput("[+] 全局令牌位置已加载，共 " + globalLocations.size() + " 条，路径: " + globalLocationsPath);
    }

    /**
     * 保存全局令牌位置到磁盘
     */
    public boolean saveLocations() {
        boolean result = TokenLocationYamlIO.writeToFile(globalLocations, globalLocationsPath);
        if (result) {
            BurpExtender.printOutput("[+] 全局令牌位置已保存，共 " + globalLocations.size() + " 条");
        }
        return result;
    }

    /**
     * 获取所有全局令牌位置
     */
    public List<TokenLocation> getAllLocations() {
        return new ArrayList<>(globalLocations);
    }

    /**
     * 添加全局令牌位置
     */
    public void addLocation(TokenLocation location) {
        // 去重：如果已存在相同 type+expression，则更新
        for (int i = 0; i < globalLocations.size(); i++) {
            TokenLocation existing = globalLocations.get(i);
            if (isSameKey(existing, location)) {
                // 更新现有记录
                existing.setExpression(location.getExpression());
                existing.setDescription(location.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(location.isEnabled());
                saveLocations();
                BurpExtender.printOutput("[+] 全局令牌位置已更新: " + location.getType().name() + " - " + location.getExpression());
                return;
            }
        }
        // 新增记录
        TokenLocation newLoc = new TokenLocation(location.getType(), location.getExpression(),
                location.getDescription(), true, location.isEnabled());
        globalLocations.add(newLoc);
        saveLocations();
        BurpExtender.printOutput("[+] 全局令牌位置已添加: " + location.getType().name() + " - " + location.getExpression());
    }

    /**
     * 更新全局令牌位置
     * 按 type+expression 匹配，如果旧键不存在则按新键添加
     *
     * @param oldType      更新前的类型
     * @param oldExpression 更新前的表达式
     * @param newLocation  更新后的令牌位置
     */
    public void updateLocation(String oldType, String oldExpression, TokenLocation newLocation) {
        // 先尝试按旧键查找并更新
        for (int i = 0; i < globalLocations.size(); i++) {
            TokenLocation existing = globalLocations.get(i);
            if (existing.getType().name().equals(oldType) && existing.getExpression().equals(oldExpression)) {
                existing.setType(newLocation.getType());
                existing.setExpression(newLocation.getExpression());
                existing.setDescription(newLocation.getDescription());
                existing.setPersistToGlobal(true);
                existing.setEnabled(newLocation.isEnabled());
                saveLocations();
                BurpExtender.printOutput("[+] 全局令牌位置已更新: " + newLocation.getType().name() + " - " + newLocation.getExpression());
                return;
            }
        }
        // 旧键未找到，按新键添加
        addLocation(newLocation);
    }

    /**
     * 移除全局令牌位置
     *
     * @param type       令牌位置类型名称
     * @param expression 表达式
     */
    public void removeLocation(String type, String expression) {
        boolean removed = globalLocations.removeIf(loc ->
                loc.getType().name().equals(type) && loc.getExpression().equals(expression));
        if (removed) {
            saveLocations();
            BurpExtender.printOutput("[+] 全局令牌位置已移除: " + type + " - " + expression);
        }
    }

    /**
     * 根据持久化标志同步令牌位置
     * persistToGlobal=true: 添加或更新到全局
     * persistToGlobal=false: 从全局中移除（如果存在）
     *
     * @param location       令牌位置数据
     * @param persistToGlobal 是否持久化到全局
     */
    public void syncLocation(TokenLocation location, boolean persistToGlobal) {
        if (persistToGlobal) {
            addLocation(location);
        } else {
            removeLocation(location.getType().name(), location.getExpression());
        }
    }

    /**
     * 检查全局中是否已存在指定 type+expression 的令牌位置
     */
    public boolean containsLocation(String type, String expression) {
        for (TokenLocation loc : globalLocations) {
            if (loc.getType().name().equals(type) && loc.getExpression().equals(expression)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断两个令牌位置是否具有相同的去重键（type + expression）
     */
    private boolean isSameKey(TokenLocation a, TokenLocation b) {
        return a.getType().name().equals(b.getType().name()) && a.getExpression().equals(b.getExpression());
    }
}
