package oxff.top.api;

import burp.BurpExtender;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 全局规则管理器（单例）
 * 管理保存在 ~/.burp/repeater_manager/api_extraction_rules.yaml 中的全局规则
 * 全局规则可被任何新项目自动加载
 * 全局规则的ID使用负数，避免与项目SQLite中的正数ID冲突
 */
public class GlobalRuleManager {
    private static GlobalRuleManager instance;

    private static final String GLOBAL_DIR_NAME = ".burp" + File.separator + "repeater_manager";
    private static final String GLOBAL_RULES_FILE = "api_extraction_rules.yaml";

    private final String globalRulesPath;
    private List<ApiExtractionRule> globalRules;
    private final AtomicInteger idGenerator = new AtomicInteger(-1); // 负数ID生成器

    private GlobalRuleManager() {
        String userHome = System.getProperty("user.home");
        this.globalRulesPath = userHome + File.separator + GLOBAL_DIR_NAME + File.separator + GLOBAL_RULES_FILE;
        this.globalRules = new ArrayList<>();
    }

    /**
     * 获取单例实例
     */
    public static synchronized GlobalRuleManager getInstance() {
        if (instance == null) {
            instance = new GlobalRuleManager();
        }
        return instance;
    }

    /**
     * 获取全局规则文件路径
     */
    public String getGlobalRulesPath() {
        return globalRulesPath;
    }

    /**
     * 从磁盘加载全局规则
     */
    public void loadRules() {
        globalRules = ApiRuleYamlIO.readFromFile(globalRulesPath);
        // 为全局规则分配负数ID
        for (ApiExtractionRule rule : globalRules) {
            rule.setId(idGenerator.getAndDecrement());
            rule.setPersistent(false); // 全局规则不持久化到项目SQLite
            rule.setGlobal(true);
        }
        BurpExtender.printOutput("[+] 全局API提取规则已加载，共 " + globalRules.size() + " 条，路径: " + globalRulesPath);
    }

    /**
     * 保存全局规则到磁盘
     */
    public boolean saveRules() {
        boolean result = ApiRuleYamlIO.writeToFile(globalRules, globalRulesPath);
        if (result) {
            BurpExtender.printOutput("[+] 全局API提取规则已保存，共 " + globalRules.size() + " 条");
        }
        return result;
    }

    /**
     * 获取所有全局规则
     */
    public List<ApiExtractionRule> getAllRules() {
        return new ArrayList<>(globalRules);
    }

    /**
     * 添加全局规则
     *
     * @return 分配的负数ID
     */
    public int addRule(ApiExtractionRule rule) {
        int id = idGenerator.getAndDecrement();
        rule.setId(id);
        rule.setPersistent(false);
        rule.setGlobal(true);
        globalRules.add(rule);
        saveRules();
        BurpExtender.printOutput("[+] 全局规则已添加，ID: " + id + "，名称: " + rule.getName());
        return id;
    }

    /**
     * 更新全局规则
     */
    public boolean updateRule(ApiExtractionRule rule) {
        for (int i = 0; i < globalRules.size(); i++) {
            if (globalRules.get(i).getId() == rule.getId()) {
                rule.setPersistent(false);
                rule.setGlobal(true);
                globalRules.set(i, rule);
                saveRules();
                BurpExtender.printOutput("[+] 全局规则已更新，ID: " + rule.getId());
                return true;
            }
        }
        BurpExtender.printError("[!] 全局规则更新失败，未找到ID: " + rule.getId());
        return false;
    }

    /**
     * 删除全局规则
     */
    public boolean deleteRule(int id) {
        boolean removed = globalRules.removeIf(rule -> rule.getId() == id);
        if (removed) {
            saveRules();
            BurpExtender.printOutput("[+] 全局规则已删除，ID: " + id);
        } else {
            BurpExtender.printError("[!] 全局规则删除失败，未找到ID: " + id);
        }
        return removed;
    }

    /**
     * 根据ID获取全局规则
     */
    public ApiExtractionRule getRuleById(int id) {
        for (ApiExtractionRule rule : globalRules) {
            if (rule.getId() == id) {
                return rule;
            }
        }
        return null;
    }

    /**
     * 替换所有全局规则（用于导入替换模式）
     */
    public void replaceAllRules(List<ApiExtractionRule> newRules) {
        globalRules.clear();
        idGenerator.set(-1); // 重置ID生成器
        for (ApiExtractionRule rule : newRules) {
            rule.setId(idGenerator.getAndDecrement());
            rule.setPersistent(false);
            rule.setGlobal(true);
            globalRules.add(rule);
        }
        saveRules();
        BurpExtender.printOutput("[+] 全局规则已替换，共 " + globalRules.size() + " 条");
    }

    /**
     * 合并规则到全局（用于导入合并模式）
     * 基于 source + method + expression 去重
     *
     * @param newRules 要合并的规则列表
     * @return 实际新增的规则数量
     */
    public int mergeRules(List<ApiExtractionRule> newRules) {
        int added = 0;
        for (ApiExtractionRule newRule : newRules) {
            boolean exists = false;
            for (ApiExtractionRule existing : globalRules) {
                if (existing.getSource() == newRule.getSource()
                        && existing.getMethod() == newRule.getMethod()
                        && existing.getExpression().equals(newRule.getExpression())) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                newRule.setId(idGenerator.getAndDecrement());
                newRule.setPersistent(false);
                newRule.setGlobal(true);
                globalRules.add(newRule);
                added++;
            }
        }
        if (added > 0) {
            saveRules();
        }
        BurpExtender.printOutput("[+] 全局规则合并完成，新增 " + added + " 条，总计 " + globalRules.size() + " 条");
        return added;
    }

    /**
     * 删除所有全局规则
     */
    public boolean deleteAllRules() {
        globalRules.clear();
        return saveRules();
    }
}
