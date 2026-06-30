package org.oxff.repeater.db.pool;

import org.oxff.repeater.logging.LogManager;
import org.oxff.repeater.db.DatabaseManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * 文件型 Body 存储管理器
 * 管理磁盘上的大体积/二进制 Body 数据文件
 */
public class FileStorageManager {

    /**
     * 写入 Body 数据到文件
     * 使用临时文件 + 原子重命名保证写入安全性
     *
     * @param data Body 字节数据
     * @param hash 内容哈希值
     * @return 相对路径（相对于数据库父目录），如 "blobs/ab/ab3f7c...hash"
     */
    public String writeBodyFile(byte[] data, String hash) {
        if (data == null || hash == null) {
            return null;
        }

        try {
            File baseDir = getBlobsBaseDir();
            if (baseDir == null) {
                LogManager.getInstance().printError("[!] 无法确定 blobs 基础目录");
                return null;
            }

            // 生成相对路径: blobs/ab/ab3f7c...hash
            String prefix = hash.substring(0, 2);
            String relativePath = "blobs/" + prefix + "/" + hash;

            File targetFile = new File(baseDir, relativePath);

            // 如果文件已存在（相同哈希 = 相同内容），直接返回
            if (targetFile.exists() && targetFile.length() == data.length) {
                return relativePath;
            }

            // 确保子目录存在
            File parentDir = targetFile.getParentFile();
            if (!parentDir.exists() && !parentDir.mkdirs()) {
                LogManager.getInstance().printError("[!] 无法创建目录: " + parentDir.getAbsolutePath());
                return null;
            }

            // 写入临时文件，然后原子重命名
            File tempFile = new File(parentDir, ".tmp_" + hash + "_" + System.currentTimeMillis());
            try {
                Files.write(tempFile.toPath(), data);

                // 原子重命名：优先使用 ATOMIC_MOVE，Windows 上不可靠时回退普通移动
                try {
                    Files.move(tempFile.toPath(), targetFile.toPath(),
                            StandardCopyOption.REPLACE_EXISTING,
                            StandardCopyOption.ATOMIC_MOVE);
                } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                    // Windows 上 ATOMIC_MOVE 可能不受支持，回退非原子移动
                    Files.move(tempFile.toPath(), targetFile.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                }

                return relativePath;
            } finally {
                // 清理可能残留的临时文件
                if (tempFile.exists()) {
                    try {
                        Files.deleteIfExists(tempFile.toPath());
                    } catch (IOException ignored) {
                        // 忽略清理失败，临时文件在下次写入时会被覆盖
                    }
                }
            }
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 写入 Body 文件失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从文件读取 Body 数据
     *
     * @param relativePath 相对路径
     * @return Body 字节数据，读取失败返回 null
     */
    public byte[] readBodyFile(String relativePath) {
        if (relativePath == null || relativePath.isEmpty()) {
            return null;
        }

        try {
            File baseDir = getBlobsBaseDir();
            if (baseDir == null) {
                return null;
            }

            File file = new File(baseDir, relativePath);
            if (!file.exists()) {
                LogManager.getInstance().printError("[!] Body 文件不存在: " + file.getAbsolutePath());
                return null;
            }

            return Files.readAllBytes(file.toPath());
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 读取 Body 文件失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 删除 Body 文件
     *
     * @param relativePath 相对路径
     * @return true 如果删除成功或文件不存在
     */
    public boolean deleteBodyFile(String relativePath) {
        if (relativePath == null || relativePath.isEmpty()) {
            return true;
        }

        try {
            File baseDir = getBlobsBaseDir();
            if (baseDir == null) {
                return false;
            }

            File file = new File(baseDir, relativePath);
            boolean deleted = !file.exists() || Files.deleteIfExists(file.toPath());

            // 尝试清理空的前缀目录
            if (deleted) {
                File parentDir = file.getParentFile();
                if (parentDir != null && parentDir.exists()) {
                    String[] remaining = parentDir.list();
                    if (remaining == null || remaining.length == 0) {
                        parentDir.delete();
                    }
                }
            }

            return deleted;
        } catch (IOException e) {
            LogManager.getInstance().printError("[!] 删除 Body 文件失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 检查 Body 文件是否已存在
     *
     * @param hash 内容哈希值
     * @return true 如果文件已存在
     */
    public boolean bodyFileExists(String hash) {
        if (hash == null) {
            return false;
        }

        File baseDir = getBlobsBaseDir();
        if (baseDir == null) {
            return false;
        }

        String prefix = hash.substring(0, 2);
        File file = new File(baseDir, "blobs/" + prefix + "/" + hash);
        return file.exists();
    }

    /**
     * 获取 blobs 基础目录（数据库文件所在目录）
     */
    private File getBlobsBaseDir() {
        String dbPath = DatabaseManager.getInstance().getDatabaseFilePath();
        if (dbPath == null) {
            return null;
        }
        File dbFile = new File(dbPath);
        return dbFile.getParentFile();
    }
}
