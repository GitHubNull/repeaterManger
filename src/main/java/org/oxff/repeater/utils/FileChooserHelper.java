package org.oxff.repeater.utils;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.DatabaseManager;
import org.oxff.repeater.config.DatabaseConfig;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;

/**
 * 文件对话框工具类 - 封装"记住上次打开目录"的逻辑
 * 所有涉及文件导航弹窗的操作统一通过此工具类创建和显示 JFileChooser
 * 上次打开的目录持久化到插件全局配置文件，插件卸载重载后仍然记住
 */
public class FileChooserHelper {

    // 配置键前缀
    private static final String CONFIG_KEY_PREFIX = "file.dialog.last_dir.";

    // 操作类型常量
    public static final String OP_ERM_IMPORT = "erm_import";
    public static final String OP_ERM_EXPORT = "erm_export";
    public static final String OP_POSTMAN_IMPORT = "postman_import";
    public static final String OP_POSTMAN_EXPORT = "postman_export";
    public static final String OP_REPORT_EXPORT = "report_export";
    public static final String OP_REPORT_IMPORT = "report_import";
    public static final String OP_REPORT_SAVE = "report_save";
    public static final String OP_YAML_RULE_EXPORT = "yaml_rule_export";
    public static final String OP_YAML_RULE_IMPORT = "yaml_rule_import";
    public static final String OP_SESSION_YAML_EXPORT = "session_yaml_export";
    public static final String OP_SESSION_YAML_IMPORT = "session_yaml_import";
    public static final String OP_RESPONSE_SAVE = "response_save";
    public static final String OP_LOG_EXPORT = "log_export";
    public static final String OP_STORAGE_DIRECTORY = "storage_directory";
    public static final String OP_LOG_DIRECTORY = "log_directory";

    /**
     * 创建已配置好上次目录的 JFileChooser
     *
     * @param operationType 操作类型，用于确定配置键
     * @param title         对话框标题
     * @return 已配置的 JFileChooser 实例
     */
    public static JFileChooser createChooser(String operationType, String title) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(title);
        setLastDirectory(chooser, operationType);
        return chooser;
    }

    /**
     * 创建已配置好上次目录的 JFileChooser，并指定初始目录优先路径
     * 用于 StorageConfigTab 等需要优先使用配置存储路径的场景
     *
     * @param operationType    操作类型
     * @param title            对话框标题
     * @param preferredDir     优先使用的初始目录（如果存在），不存在时回退到上次记忆目录
     * @return 已配置的 JFileChooser 实例
     */
    public static JFileChooser createChooserWithPreferredDir(String operationType, String title, String preferredDir) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle(title);

        // 优先使用指定目录
        if (preferredDir != null && !preferredDir.isEmpty()) {
            File preferred = new File(preferredDir);
            if (preferred.exists()) {
                chooser.setCurrentDirectory(preferred);
                return chooser;
            }
        }

        // 回退到上次记忆目录
        setLastDirectory(chooser, operationType);
        return chooser;
    }

    /**
     * 显示打开文件对话框，并在用户确认后保存选择的目录到配置
     *
     * @param operationType 操作类型
     * @param title         对话框标题
     * @param parent        父组件
     * @param filters       文件过滤器（可选，可传多个）
     * @return 用户选择的文件，取消或关闭时返回 null
     */
    public static File showOpenDialog(String operationType, String title, Component parent,
                                      FileNameExtensionFilter... filters) {
        JFileChooser chooser = createChooser(operationType, title);

        if (filters != null && filters.length > 0) {
            for (FileNameExtensionFilter filter : filters) {
                chooser.setFileFilter(filter);
            }
            // 如果只有一个过滤器，禁用"接受所有文件"选项
            if (filters.length == 1) {
                chooser.setAcceptAllFileFilterUsed(false);
            }
        }

        int result = chooser.showOpenDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            saveLastDirectory(chooser, operationType);
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * 显示保存文件对话框，并在用户确认后保存选择的目录到配置
     *
     * @param operationType 操作类型
     * @param title         对话框标题
     * @param parent        父组件
     * @param defaultFile   默认文件名（可选，null时不设置）
     * @param filters       文件过滤器（可选）
     * @return 用户选择的文件，取消或关闭时返回 null
     */
    public static File showSaveDialog(String operationType, String title, Component parent,
                                      File defaultFile, FileNameExtensionFilter... filters) {
        JFileChooser chooser = createChooser(operationType, title);

        if (defaultFile != null) {
            chooser.setSelectedFile(defaultFile);
        }

        if (filters != null && filters.length > 0) {
            for (FileNameExtensionFilter filter : filters) {
                chooser.setFileFilter(filter);
            }
        }

        int result = chooser.showSaveDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            saveLastDirectory(chooser, operationType);
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * 显示目录选择对话框（DIRECTORIES_ONLY），并在用户确认后保存选择的目录到配置
     * 对于目录选择，保存的是选中的目录本身（而非其父目录）
     *
     * @param operationType    操作类型
     * @param title            对话框标题
     * @param parent           父组件
     * @param preferredDir     优先使用的初始目录（可选，null时不优先）
     * @return 用户选择的目录，取消或关闭时返回 null
     */
    public static File showDirectoryDialog(String operationType, String title, Component parent,
                                           String preferredDir) {
        JFileChooser chooser;
        if (preferredDir != null && !preferredDir.isEmpty()) {
            chooser = createChooserWithPreferredDir(operationType, title, preferredDir);
        } else {
            chooser = createChooser(operationType, title);
        }
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int result = chooser.showOpenDialog(parent);
        if (result == JFileChooser.APPROVE_OPTION) {
            // 对于目录选择，保存选中的目录本身
            File selectedDir = chooser.getSelectedFile();
            saveDirectoryToConfig(operationType, selectedDir.getAbsolutePath());
            return selectedDir;
        }
        return null;
    }

    /**
     * 显示已有的 JFileChooser 并在确认后保存目录
     * 适用于需要更复杂配置的场景（如加密选项、多步骤操作等）
     *
     * @param chooser       已配置的 JFileChooser 实例
     * @param operationType 操作类型
     * @param parent        父组件
     * @param dialogType    JFileChooser.OPEN_DIALOG 或 JFileChooser.SAVE_DIALOG
     * @return JFileChooser 的返回值 (APPROVE_OPTION, CANCEL_OPTION 等)
     */
    public static int showAndRemember(JFileChooser chooser, String operationType,
                                      Component parent, int dialogType) {
        int result;
        if (dialogType == JFileChooser.SAVE_DIALOG) {
            result = chooser.showSaveDialog(parent);
        } else {
            result = chooser.showOpenDialog(parent);
        }

        if (result == JFileChooser.APPROVE_OPTION) {
            // 判断是否是目录选择模式
            if (chooser.getFileSelectionMode() == JFileChooser.DIRECTORIES_ONLY) {
                saveDirectoryToConfig(operationType, chooser.getSelectedFile().getAbsolutePath());
            } else {
                saveLastDirectory(chooser, operationType);
            }
        }
        return result;
    }

    // ========== 内部方法 ==========

    /**
     * 从配置中读取上次目录并设置到 chooser
     */
    private static void setLastDirectory(JFileChooser chooser, String operationType) {
        DatabaseConfig config = getConfig();
        String lastDir = config.getProperty(CONFIG_KEY_PREFIX + operationType, "");
        if (lastDir != null && !lastDir.isEmpty()) {
            File dir = new File(lastDir);
            if (dir.exists()) {
                chooser.setCurrentDirectory(dir);
            }
        }
    }

    /**
     * 保存选择文件的父目录到配置
     */
    private static void saveLastDirectory(JFileChooser chooser, String operationType) {
        File selectedFile = chooser.getSelectedFile();
        if (selectedFile != null) {
            File parentDir = selectedFile.getParentFile();
            if (parentDir != null) {
                saveDirectoryToConfig(operationType, parentDir.getAbsolutePath());
            }
        }
    }

    /**
     * 保存目录路径到配置文件
     */
    private static void saveDirectoryToConfig(String operationType, String dirPath) {
        try {
            DatabaseConfig config = getConfig();
            config.setProperty(CONFIG_KEY_PREFIX + operationType, dirPath);
            config.saveConfig();
            LogManager.getInstance().printOutput("[+] 已记住文件对话框目录 (" + operationType + "): " + dirPath);
        } catch (Exception e) {
            LogManager.getInstance().printError("[!] 保存文件对话框目录配置失败: " + e.getMessage());
        }
    }

    /**
     * 获取 DatabaseConfig 实例
     */
    private static DatabaseConfig getConfig() {
        return DatabaseManager.getInstance().getConfig();
    }
}