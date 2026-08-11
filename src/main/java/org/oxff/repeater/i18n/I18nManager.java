package org.oxff.repeater.i18n;

import org.oxff.repeater.config.DatabaseConfig;
import org.oxff.repeater.db.DatabaseManager;

import javax.swing.SwingUtilities;
import java.text.MessageFormat;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 国际化（i18n）管理器 — 单例模式。
 *
 * <p>职责：</p>
 * <ul>
 *   <li>加载和管理 ResourceBundle（中文 zh_CN / 英文 en_US）</li>
 *   <li>提供 getString / tr 文本获取接口（支持 MessageFormat 参数化）</li>
 *   <li>运行时动态切换语言，通过监听器机制通知所有已注册 UI 组件刷新文本</li>
 *   <li>持久化用户语言偏好（复用 DatabaseConfig，键 ui.language）</li>
 * </ul>
 *
 * <p>使用方式：</p>
 * <pre>
 *   // 获取文本
 *   String text = I18nManager.tr("toolbar.mode.normal");
 *   String formatted = I18nManager.tr("log.requests.loaded", count);
 *
 *   // 注册语言变更监听（UI 组件构造时）
 *   I18nManager.getInstance().addLocaleChangeListener(this::refreshTexts);
 * </pre>
 */
public class I18nManager {

    private static final Logger LOGGER = Logger.getLogger(I18nManager.class.getName());

    /** 中文（简体） */
    public static final Locale LOCALE_ZH = Locale.SIMPLIFIED_CHINESE;
    /** 英文（美国） */
    public static final Locale LOCALE_EN = Locale.US;

    /** ResourceBundle 基础名（对应 resources/i18n/messages.properties） */
    private static final String BUNDLE_BASE = "i18n.messages";

    /** 语言偏好持久化键 */
    private static final String CONFIG_KEY_LANGUAGE = "ui.language";

    /** 语言代码：中文 */
    private static final String LANG_ZH_CN = "zh_CN";
    /** 语言代码：英文 */
    private static final String LANG_EN_US = "en_US";

    private static volatile I18nManager instance;

    private volatile ResourceBundle bundle;
    private volatile Locale currentLocale;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    private I18nManager() {
        // 默认中文，initialize() 会根据持久化配置覆盖
        this.currentLocale = LOCALE_ZH;
        loadBundle();
    }

    /**
     * 获取单例实例（双重检查锁）
     */
    public static I18nManager getInstance() {
        if (instance == null) {
            synchronized (I18nManager.class) {
                if (instance == null) {
                    instance = new I18nManager();
                }
            }
        }
        return instance;
    }

    /**
     * 初始化：从持久化配置读取语言偏好并应用。
     * 应在插件启动、创建任何 UI 之前调用。
     * 失败时回退到中文，不阻断启动。
     */
    public void initialize() {
        try {
            DatabaseConfig config = DatabaseManager.getInstance().getConfig();
            String lang = config.getProperty(CONFIG_KEY_LANGUAGE, LANG_ZH_CN);
            currentLocale = LANG_EN_US.equals(lang) ? LOCALE_EN : LOCALE_ZH;
            loadBundle();
            LOGGER.info("[i18n] 语言偏好已加载: " + currentLocale);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[i18n] 语言偏好加载失败，回退到中文", e);
            currentLocale = LOCALE_ZH;
            loadBundle();
        }
    }

    /**
     * 加载当前 Locale 对应的 ResourceBundle
     */
    private void loadBundle() {
        try {
            ResourceBundle.clearCache();
            bundle = ResourceBundle.getBundle(BUNDLE_BASE, currentLocale);
        } catch (MissingResourceException e) {
            LOGGER.log(Level.SEVERE, "[i18n] 资源包加载失败: " + BUNDLE_BASE, e);
            bundle = null;
        }
    }

    /**
     * 获取指定键对应的文本。
     * 键缺失时返回 "!key!" 便于排查。
     *
     * @param key 资源键
     * @return 本地化文本
     */
    public String getString(String key) {
        if (bundle == null) {
            return "!" + key + "!";
        }
        try {
            return bundle.getString(key);
        } catch (MissingResourceException e) {
            LOGGER.fine("[i18n] 缺失资源键: " + key);
            return "!" + key + "!";
        }
    }

    /**
     * 获取指定键对应的文本，并使用 MessageFormat 格式化参数。
     *
     * @param key  资源键
     * @param args 格式化参数
     * @return 格式化后的本地化文本
     */
    public String getString(String key, Object... args) {
        String pattern = getString(key);
        if (args == null || args.length == 0) {
            return pattern;
        }
        try {
            return MessageFormat.format(pattern, args);
        } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "[i18n] 格式化失败: " + key, e);
            return pattern;
        }
    }

    /**
     * 便捷静态方法：获取文本。
     *
     * @param key 资源键
     * @return 本地化文本
     */
    public static String tr(String key) {
        return getInstance().getString(key);
    }

    /**
     * 便捷静态方法：获取文本并格式化。
     *
     * @param key  资源键
     * @param args 格式化参数
     * @return 格式化后的本地化文本
     */
    public static String tr(String key, Object... args) {
        return getInstance().getString(key, args);
    }

    /**
     * 获取当前语言环境
     */
    public Locale getCurrentLocale() {
        return currentLocale;
    }

    /**
     * 当前是否为英文
     */
    public boolean isEnglish() {
        return LOCALE_EN.equals(currentLocale);
    }

    /**
     * 切换语言环境。
     * 依次执行：更新 Locale → 重载 ResourceBundle → 持久化偏好 → 通知所有监听器（EDT）。
     *
     * @param locale 目标语言环境
     */
    public void setLocale(Locale locale) {
        if (locale == null || locale.equals(currentLocale)) {
            return;
        }
        currentLocale = locale;
        loadBundle();
        persistLanguagePreference();
        notifyListeners();
        LOGGER.info("[i18n] 语言已切换为: " + locale);
    }

    /**
     * 持久化语言偏好到 DatabaseConfig
     */
    private void persistLanguagePreference() {
        try {
            DatabaseConfig config = DatabaseManager.getInstance().getConfig();
            config.setProperty(CONFIG_KEY_LANGUAGE, isEnglish() ? LANG_EN_US : LANG_ZH_CN);
            config.saveConfig();
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "[i18n] 语言偏好持久化失败", e);
        }
    }

    /**
     * 注册语言变更监听器。
     * 回调将在 EDT 线程中执行。
     *
     * @param listener 语言变更后要执行的刷新逻辑
     */
    public void addLocaleChangeListener(Runnable listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * 移除语言变更监听器
     */
    public void removeLocaleChangeListener(Runnable listener) {
        listeners.remove(listener);
    }

    /**
     * 通知所有监听器（确保在 EDT 中执行）
     */
    private void notifyListeners() {
        for (Runnable listener : listeners) {
            try {
                if (SwingUtilities.isEventDispatchThread()) {
                    listener.run();
                } else {
                    SwingUtilities.invokeLater(listener);
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "[i18n] 语言变更监听器执行异常", e);
            }
        }
    }
}
