package org.oxff.repeater.config;

import org.oxff.repeater.logging.LogManager;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 会话目录封装类 - 管理一次插件会话的所有数据文件
 * <p>
 * 每次加载插件时创建一个以时间戳命名的会话目录，内含：
 * - repeater_manager.sqlite3  数据库文件（固定名称）
 * - blobs/                    body 数据文件
 * - logs/                     日志文件
 */
public class SessionDirectory {

    /** 数据库文件固定名称 */
    public static final String DATABASE_FILENAME = "repeater_manager.sqlite3";

    /** blobs 子目录名 */
    private static final String BLOBS_DIR_NAME = "blobs";

    /** logs 子目录名 */
    private static final String LOGS_DIR_NAME = "logs";

    /** 会话目录 */
    private final File directory;

    /**
     * 从显式目录路径构造
     *
     * @param directory 会话目录
     */
    public SessionDirectory(File directory) {
        this.directory = directory;
    }

    /**
     * 在指定基础目录下创建新的时间戳会话目录
     * 如果目录名冲突则追加 _2, _3 等后缀
     *
     * @param baseDir 基础目录
     * @return 新创建的 SessionDirectory 实例
     */
    public static SessionDirectory createNew(String baseDir) {
        String dirName = generateSessionDirectoryName();
        File sessionDir = new File(baseDir, dirName);

        // 冲突避免：如果目录已存在，追加 _2, _3 等
        if (sessionDir.exists()) {
            int suffix = 2;
            while (new File(baseDir, dirName + "_" + suffix).exists()) {
                suffix++;
            }
            sessionDir = new File(baseDir, dirName + "_" + suffix);
            LogManager.getInstance().printOutput("[*] 会话目录名冲突，使用: " + sessionDir.getName());
        }

        return new SessionDirectory(sessionDir);
    }

    /**
     * 生成会话目录名称
     * 格式: repeater_manager_YYYY_MMDD_HHmm_ssSSS
     * 与原数据库文件名格式一致（去掉 .sqlite3 后缀）
     *
     * @return 会话目录名称
     */
    public static String generateSessionDirectoryName() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy_MMdd_HHmm_ssSSS");
        return "repeater_manager_" + sdf.format(new Date());
    }

    /**
     * 获取会话目录本身
     */
    public File getDirectory() {
        return directory;
    }

    /**
     * 获取数据库文件路径
     * 格式: session_dir/repeater_manager.sqlite3
     */
    public File getDatabaseFile() {
        return new File(directory, DATABASE_FILENAME);
    }

    /**
     * 获取 blobs 目录
     * 格式: session_dir/blobs/
     */
    public File getBlobsDir() {
        return new File(directory, BLOBS_DIR_NAME);
    }

    /**
     * 获取日志目录
     * 格式: session_dir/logs/
     */
    public File getLogsDir() {
        return new File(directory, LOGS_DIR_NAME);
    }

    /**
     * 确保会话目录及其子目录已创建
     * 创建: session_dir/, session_dir/blobs/, session_dir/logs/
     *
     * @return true 如果目录结构已就绪
     */
    public boolean ensureCreated() {
        if (!directory.exists() && !directory.mkdirs()) {
            LogManager.getInstance().printError("[!] 无法创建会话目录: " + directory.getAbsolutePath());
            return false;
        }

        File blobsDir = getBlobsDir();
        if (!blobsDir.exists() && !blobsDir.mkdirs()) {
            LogManager.getInstance().printError("[!] 无法创建 blobs 目录: " + blobsDir.getAbsolutePath());
            return false;
        }

        File logsDir = getLogsDir();
        if (!logsDir.exists() && !logsDir.mkdirs()) {
            LogManager.getInstance().printError("[!] 无法创建日志目录: " + logsDir.getAbsolutePath());
            return false;
        }

        return true;
    }

    /**
     * 获取会话目录的绝对路径
     */
    public String getAbsolutePath() {
        return directory.getAbsolutePath();
    }

    @Override
    public String toString() {
        return directory.getAbsolutePath();
    }
}
