package org.oxff.repeater.io;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.oxff.repeater.db.DatabaseManager;

import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32;
import java.util.zip.Inflater;

/**
 * ERM 存档导入器
 * 读取并验证 .erm 存档文件，提取数据库和 blob 文件
 * 支持可选的 AES-256-CBC + HMAC-SHA256 解密
 */
public class ErmArchiveReader {

    private final DatabaseManager dbManager;
    private final AtomicBoolean isImporting = new AtomicBoolean(false);

    public ErmArchiveReader() {
        this.dbManager = DatabaseManager.getInstance();
    }

    // ========== 数据类 ==========

    /**
     * 文件头解析结果
     */
    public static class HeaderData {
        public int formatVersion;
        public int flags;
        public int entryCount;
        public long manifestOffset;
        public int schemaVersion;
        public int headerSize;
        public boolean isEncrypted;
    }

    /**
     * 数据条目头解析结果
     */
    public static class EntryHeader {
        public String path;
        public int compressionMethod;
        public long compressedSize;
        public long uncompressedSize;
        public long entryCrc;
    }

    // ========== 公开接口 ==========

    /**
     * 从 ERM 存档文件导入（UI入口）
     */
    public boolean importFromFile(Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                    "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        File selectedFile = org.oxff.repeater.utils.FileChooserHelper.showOpenDialog(
                org.oxff.repeater.utils.FileChooserHelper.OP_ERM_IMPORT, "导入ERM存档", parent,
                new FileNameExtensionFilter("ERM存档 (*.erm)", "erm"));

        if (selectedFile == null) {
            return false;
        }

        if (!selectedFile.exists() || !selectedFile.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(selectedFile, parent);
                javax.swing.SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(parent, "ERM存档导入成功", "导入成功",
                                JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入ERM存档失败: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(parent,
                                "导入数据失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE));
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    /**
     * 从指定文件路径导入（供 DataImporter.smartImport 调用，不再弹出文件对话框）
     */
    public boolean importFromPath(File file, Component parent) {
        if (isImporting.get()) {
            JOptionPane.showMessageDialog(parent,
                    "另一个导入操作正在进行中，请稍后再试。", "导入繁忙", JOptionPane.WARNING_MESSAGE);
            return false;
        }

        if (!file.exists() || !file.isFile()) {
            JOptionPane.showMessageDialog(parent, "所选文件不存在", "导入错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        isImporting.set(true);
        CompletableFuture.runAsync(() -> {
            try {
                doImport(file, parent);
                javax.swing.SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(parent, "ERM存档导入成功", "导入成功",
                                JOptionPane.INFORMATION_MESSAGE));
            } catch (Exception e) {
                BurpExtender.printError("[!] 导入ERM存档失败: " + e.getMessage());
                javax.swing.SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(parent,
                                "导入数据失败: " + e.getMessage(), "导入错误", JOptionPane.ERROR_MESSAGE));
            } finally {
                isImporting.set(false);
            }
        });

        return true;
    }

    // ========== 核心导入逻辑 ==========

    /**
     * 执行导入操作
     */
    private void doImport(File ermFile, Component parent) throws Exception {
        BurpExtender.printOutput("[*] 开始ERM存档导入...");

        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(ermFile, "r");

            // 1. 读取并验证文件头
            HeaderData header = readHeader(raf);
            BurpExtender.printOutput("[+] 文件头验证通过: format_version=" + header.formatVersion
                    + ", encrypted=" + header.isEncrypted + ", entries=" + header.entryCount
                    + ", schema_version=" + header.schemaVersion);

            // 2. 验证文件尾
            boolean footerValid = verifyFooter(raf);
            if (!footerValid) {
                BurpExtender.printOutput("[!] 文件尾校验失败，存档可能被截断");
            }

            // 3. 如果加密，获取密码并解密
            byte[] entriesData;
            if (header.isEncrypted) {
                entriesData = decryptEntries(raf, header, parent);
                if (entriesData == null) {
                    throw new IOException("解密失败");
                }
            } else {
                // 未加密：读取头部之后、尾部之前的所有数据
                long dataStart = ErmFormatConstants.HEADER_SIZE;
                long fileLength = raf.length();
                long dataEnd = fileLength - ErmFormatConstants.FOOTER_SIZE;
                int dataLength = (int) (dataEnd - dataStart);

                raf.seek(dataStart);
                entriesData = new byte[dataLength];
                raf.readFully(entriesData);
            }

            // 4. 解析清单
            ManifestInfo manifestInfo = parseManifest(entriesData, header);
            BurpExtender.printOutput("[+] 清单解析成功: app_version=" + manifestInfo.appVersion
                    + ", format_version=" + manifestInfo.formatVersion
                    + ", schema_version=" + manifestInfo.schemaVersion
                    + ", blob_count=" + manifestInfo.blobCount
                    + ", total_entries=" + manifestInfo.totalEntries);

            // 4.1 校验清单格式版本一致性
            if (manifestInfo.formatVersion != header.formatVersion) {
                BurpExtender.printOutput("[!] 清单格式版本(" + manifestInfo.formatVersion
                        + ")与文件头(" + header.formatVersion + ")不一致，以文件头为准");
            }

            // 4.2 校验清单schema版本兼容性
            if (manifestInfo.schemaVersion > ErmFormatConstants.CURRENT_SCHEMA_VERSION) {
                throw new IOException("存档schema版本(" + manifestInfo.schemaVersion
                        + ")高于当前支持的版本(" + ErmFormatConstants.CURRENT_SCHEMA_VERSION
                        + ")，请升级插件后重试");
            }

            // 4.3 构建存档信息摘要
            String createdTimeStr = manifestInfo.createdAt > 0
                    ? new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(manifestInfo.createdAt))
                    : "未知";
            String archiveSummary = "存档信息:\n"
                    + "  来源版本: " + manifestInfo.appVersion + "\n"
                    + "  创建时间: " + createdTimeStr + "\n"
                    + "  条目数量: " + manifestInfo.totalEntries + " (其中blob文件: " + manifestInfo.blobCount + ")\n"
                    + "  Schema版本: " + manifestInfo.schemaVersion
                    + (header.isEncrypted ? "\n  加密: 是" : "");

            // 5. 确认导入（在 EDT 线程中执行）
            boolean[] confirmed = {false};
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                int confirm = JOptionPane.showConfirmDialog(parent,
                        "导入操作将使用新的数据库文件，当前会话数据将不可用。\n\n"
                                + archiveSummary + "\n\n是否继续？",
                        "确认导入", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                confirmed[0] = (confirm == JOptionPane.YES_OPTION);
            });

            if (!confirmed[0]) {
                return;
            }

            // 6. 生成目标路径
            String newDbPath = dbManager.getConfig().getEffectiveDatabasePath();
            File targetFile = new File(newDbPath);
            File targetDir = targetFile.getParentFile();
            if (targetDir != null && !targetDir.exists()) {
                targetDir.mkdirs();
            }

            // 7. 提取所有条目（使用清单中指定的数据库条目路径）
            String dbEntryPath = manifestInfo.dbEntry != null ? manifestInfo.dbEntry : ErmFormatConstants.DB_ENTRY_PATH;
            int[] results = extractEntries(entriesData, targetDir, targetFile, header.entryCount, dbEntryPath);
            int successCount = results[0];
            int failCount = results[1];

            BurpExtender.printOutput("[+] 条目提取完成: 成功=" + successCount + ", 失败=" + failCount);

            // 8. 检查关键条目
            if (!targetFile.exists()) {
                throw new IOException("数据库条目提取失败，无法切换会话");
            }

            // 9. 切换会话
            dbManager.getConfig().setSessionFile(newDbPath);
            dbManager.resetForNewSession();

            boolean success = dbManager.initialize();
            if (!success) {
                throw new SQLException("导入数据库后初始化失败");
            }

            // 重定位日志到新会话目录
            org.oxff.repeater.logging.LogManager.getInstance().relocateFileHandler(
                dbManager.getLogsDirectory().getAbsolutePath());

            BurpExtender.printOutput("[+] ERM存档导入成功，新数据库: " + newDbPath);

            // 10. 刷新 UI
            refreshUIAfterImport();

        } finally {
            if (raf != null) {
                try { raf.close(); } catch (IOException ignored) {}
            }
        }
    }

    // ========== 文件头读取 ==========

    /**
     * 读取并验证 32 字节文件头
     */
    private HeaderData readHeader(RandomAccessFile raf) throws IOException {
        raf.seek(0);
        byte[] headerBytes = new byte[ErmFormatConstants.HEADER_SIZE];
        raf.readFully(headerBytes);

        // 验证魔法数字
        for (int i = 0; i < ErmFormatConstants.MAGIC_HEADER.length; i++) {
            if (headerBytes[i] != ErmFormatConstants.MAGIC_HEADER[i]) {
                throw new IOException("不是有效的ERM存档文件（魔法数字不匹配）");
            }
        }

        // 验证 header_crc
        CRC32 crc32 = new CRC32();
        crc32.update(headerBytes, 0, 28);
        int computedCrc = (int) crc32.getValue();
        int storedCrc = readUint32BE(headerBytes, 28);
        if (computedCrc != storedCrc) {
            throw new IOException("存档头部已损坏（CRC校验失败）");
        }

        HeaderData header = new HeaderData();
        header.formatVersion = readUint16BE(headerBytes, 4);
        header.flags = readUint32BE(headerBytes, 6);
        header.entryCount = readUint32BE(headerBytes, 10);
        header.manifestOffset = readUint64BE(headerBytes, 14);
        header.schemaVersion = readUint32BE(headerBytes, 22);
        header.headerSize = readUint16BE(headerBytes, 26);
        header.isEncrypted = (header.flags & ErmFormatConstants.FLAG_ENCRYPTED) != 0;

        // 版本检查
        if (header.formatVersion > ErmFormatConstants.FORMAT_VERSION) {
            BurpExtender.printOutput("[!] 格式版本 " + header.formatVersion
                    + " 高于当前支持的版本 " + ErmFormatConstants.FORMAT_VERSION + "，尝试继续读取");
        }

        return header;
    }

    // ========== 文件尾验证 ==========

    /**
     * 验证 16 字节文件尾
     */
    private boolean verifyFooter(RandomAccessFile raf) throws IOException {
        long fileLength = raf.length();
        if (fileLength < ErmFormatConstants.HEADER_SIZE + ErmFormatConstants.FOOTER_SIZE) {
            return false;
        }

        raf.seek(fileLength - ErmFormatConstants.FOOTER_SIZE);
        byte[] footerBytes = new byte[ErmFormatConstants.FOOTER_SIZE];
        raf.readFully(footerBytes);

        // 验证魔法数字
        for (int i = 0; i < ErmFormatConstants.MAGIC_FOOTER.length; i++) {
            if (footerBytes[i] != ErmFormatConstants.MAGIC_FOOTER[i]) {
                return false;
            }
        }

        // 验证 footer_crc
        CRC32 footerCrc = new CRC32();
        footerCrc.update(footerBytes, 0, 12);
        int computedCrc = (int) footerCrc.getValue();
        int storedCrc = readUint32BE(footerBytes, 8);
        if (computedCrc != storedCrc) {
            return false;
        }

        // 验证 data_crc
        long dataStart = ErmFormatConstants.HEADER_SIZE;
        long dataEnd = fileLength - ErmFormatConstants.FOOTER_SIZE;
        int storedDataCrc = readUint32BE(footerBytes, 4);

        CRC32 dataCrc = new CRC32();
        raf.seek(dataStart);
        byte[] buffer = new byte[ErmFormatConstants.BUFFER_SIZE];
        long remaining = dataEnd - dataStart;
        while (remaining > 0) {
            int toRead = (int) Math.min(buffer.length, remaining);
            int read = raf.read(buffer, 0, toRead);
            if (read <= 0) break;
            dataCrc.update(buffer, 0, read);
            remaining -= read;
        }

        return (int) dataCrc.getValue() == storedDataCrc;
    }

    // ========== 解密 ==========

    /**
     * 解密加密的数据条目
     */
    private byte[] decryptEntries(RandomAccessFile raf, HeaderData header, Component parent)
            throws Exception {
        // 读取加密头
        raf.seek(ErmFormatConstants.HEADER_SIZE);
        byte[] salt = new byte[ErmFormatConstants.SALT_SIZE];
        raf.readFully(salt);
        byte[] iv = new byte[ErmFormatConstants.IV_SIZE];
        raf.readFully(iv);
        byte[] expectedHmac = new byte[ErmFormatConstants.HMAC_SIZE];
        raf.readFully(expectedHmac);

        // 弹出密码输入对话框
        final char[][] passwordHolder = {null};
        javax.swing.SwingUtilities.invokeAndWait(() -> {
            passwordHolder[0] = ErmCryptoHelper.promptPasswordForImport(parent);
        });

        char[] password = passwordHolder[0];
        if (password == null) {
            throw new IOException("需要输入密码才能解密ERM存档");
        }

        try {
            // 派生密钥
            ErmCryptoHelper.KeyPair keyPair = ErmCryptoHelper.deriveKeys(password, salt);

            // 读取密文
            long cryptoHeaderEnd = ErmFormatConstants.HEADER_SIZE + ErmFormatConstants.CRYPTO_HEADER_SIZE;
            long fileLength = raf.length();
            long ciphertextLength = fileLength - cryptoHeaderEnd - ErmFormatConstants.FOOTER_SIZE;

            raf.seek(cryptoHeaderEnd);
            byte[] ciphertext = new byte[(int) ciphertextLength];
            raf.readFully(ciphertext);

            // Verify-then-Decrypt
            byte[] plaintext = ErmCryptoHelper.decrypt(ciphertext, iv, expectedHmac,
                    keyPair.aesKey, keyPair.hmacKey);

            BurpExtender.printOutput("[+] 解密成功，数据长度: " + plaintext.length);
            return plaintext;

        } finally {
            ErmCryptoHelper.clearPassword(password);
        }
    }

    // ========== 清单解析 ==========

    /**
     * 清单信息
     */
    private static class ManifestInfo {
        int formatVersion;
        String appVersion;
        long createdAt;
        int schemaVersion;
        boolean encrypted;
        String dbEntry;
        int blobCount;
        int totalEntries;
    }

    /**
     * 从条目数据中解析清单
     */
    private ManifestInfo parseManifest(byte[] entriesData, HeaderData header) throws IOException {
        // 在条目数据中找到清单（最后一个条目）
        // 从后往前搜索 .erm/MANIFEST 路径
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(entriesData));
        ManifestInfo manifestInfo = null;
        int entriesParsed = 0;

        while (dis.available() > 0 && entriesParsed < header.entryCount) {
            EntryHeader entryHeader = readEntryHeader(dis);

            if (entryHeader.path.equals(ErmFormatConstants.MANIFEST_ENTRY_PATH)) {
                // 读取清单数据
                byte[] compressedData = new byte[(int) entryHeader.compressedSize];
                dis.readFully(compressedData);

                byte[] manifestBytes;
                if (entryHeader.compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED) {
                    manifestBytes = decompressData(compressedData, (int) entryHeader.uncompressedSize);
                } else {
                    manifestBytes = compressedData;
                }

                // 验证 CRC
                CRC32 crc32 = new CRC32();
                crc32.update(manifestBytes);
                if ((int) crc32.getValue() != (int) entryHeader.entryCrc) {
                    throw new IOException("清单条目CRC校验失败");
                }

                // 解析 JSON
                String jsonStr = new String(manifestBytes, StandardCharsets.UTF_8);
                JsonObject json = new Gson().fromJson(jsonStr, JsonObject.class);

                manifestInfo = new ManifestInfo();
                manifestInfo.formatVersion = json.has("format_version") ? json.get("format_version").getAsInt() : 1;
                manifestInfo.appVersion = json.has("app_version") ? json.get("app_version").getAsString() : "unknown";
                manifestInfo.createdAt = json.has("created_at") ? json.get("created_at").getAsLong() : 0;
                manifestInfo.schemaVersion = json.has("schema_version") ? json.get("schema_version").getAsInt() : 1;
                manifestInfo.encrypted = json.has("encrypted") && json.get("encrypted").getAsBoolean();
                manifestInfo.dbEntry = json.has("db_entry") ? json.get("db_entry").getAsString() : ErmFormatConstants.DB_ENTRY_PATH;
                manifestInfo.blobCount = json.has("blob_count") ? json.get("blob_count").getAsInt() : 0;
                manifestInfo.totalEntries = json.has("total_entries") ? json.get("total_entries").getAsInt() : header.entryCount;

                // 校验加密标志一致性
                if (manifestInfo.encrypted != header.isEncrypted) {
                    throw new IOException("清单加密标志与文件头不一致，存档可能已损坏");
                }
            } else {
                // 跳过非清单条目的数据
                dis.skipBytes((int) entryHeader.compressedSize);
            }
            entriesParsed++;
        }

        if (manifestInfo == null) {
            throw new IOException("存档中未找到清单条目");
        }

        return manifestInfo;
    }

    // ========== 条目提取 ==========

    /**
     * 提取所有数据条目
     * @param dbEntryPath 清单中指定的数据库条目路径
     * @return [successCount, failCount]
     */
    private int[] extractEntries(byte[] entriesData, File targetDir, File targetDbFile,
                                 int entryCount, String dbEntryPath) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(entriesData));
        int successCount = 0;
        int failCount = 0;
        int entriesParsed = 0;

        while (dis.available() > 0 && entriesParsed < entryCount) {
            EntryHeader entryHeader;
            try {
                entryHeader = readEntryHeader(dis);
            } catch (Exception e) {
                BurpExtender.printError("[!] 解析条目头失败: " + e.getMessage());
                failCount++;
                break;
            }

            try {
                // 读取压缩数据
                byte[] compressedData = new byte[(int) entryHeader.compressedSize];
                dis.readFully(compressedData);

                // 解压
                byte[] uncompressedData;
                if (entryHeader.compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED) {
                    uncompressedData = decompressData(compressedData, (int) entryHeader.uncompressedSize);
                } else {
                    uncompressedData = compressedData;
                }

                // 验证 CRC
                CRC32 crc32 = new CRC32();
                crc32.update(uncompressedData);
                if ((int) crc32.getValue() != (int) entryHeader.entryCrc) {
                    BurpExtender.printError("[!] 条目 '" + entryHeader.path + "' CRC校验失败");
                    failCount++;
                    continue;
                }

                // 写入文件
                File targetFile;
                if (entryHeader.path.equals(dbEntryPath)) {
                    targetFile = targetDbFile;
                } else {
                    targetFile = new File(targetDir, entryHeader.path.replace('/', File.separatorChar));
                }

                // 确保父目录存在
                File parentFile = targetFile.getParentFile();
                if (parentFile != null && !parentFile.exists()) {
                    parentFile.mkdirs();
                }

                Files.write(targetFile.toPath(), uncompressedData);
                successCount++;
                BurpExtender.printOutput("[+] 提取条目: " + entryHeader.path
                        + " (" + uncompressedData.length + " bytes)");

            } catch (Exception e) {
                BurpExtender.printError("[!] 提取条目失败: " + e.getMessage());
                failCount++;
            }

            entriesParsed++;
        }

        return new int[]{successCount, failCount};
    }

    // ========== 条目头解析 ==========

    /**
     * 从流中读取一个条目头
     */
    private EntryHeader readEntryHeader(DataInputStream dis) throws IOException {
        EntryHeader header = new EntryHeader();

        // path_length (2 bytes, big-endian)
        int pathLength = ((dis.read() & 0xFF) << 8) | (dis.read() & 0xFF);

        // path
        byte[] pathBytes = new byte[pathLength];
        dis.readFully(pathBytes);
        header.path = new String(pathBytes, StandardCharsets.UTF_8);

        // compression_method (1 byte)
        header.compressionMethod = dis.read() & 0xFF;

        // compressed_size (8 bytes, big-endian)
        header.compressedSize = 0;
        for (int i = 7; i >= 0; i--) {
            header.compressedSize |= ((long) (dis.read() & 0xFF)) << (i * 8);
        }

        // uncompressed_size (8 bytes, big-endian)
        header.uncompressedSize = 0;
        for (int i = 7; i >= 0; i--) {
            header.uncompressedSize |= ((long) (dis.read() & 0xFF)) << (i * 8);
        }

        // entry_crc (4 bytes, big-endian)
        header.entryCrc = 0;
        for (int i = 3; i >= 0; i--) {
            header.entryCrc |= ((long) (dis.read() & 0xFF)) << (i * 8);
        }

        return header;
    }

    // ========== 解压 ==========

    /**
     * 使用 Inflater 解压数据
     */
    private byte[] decompressData(byte[] compressed, int uncompressedSize) throws IOException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressed);

            ByteArrayOutputStream baos = new ByteArrayOutputStream(uncompressedSize);
            byte[] buffer = new byte[ErmFormatConstants.BUFFER_SIZE];

            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count > 0) {
                    baos.write(buffer, 0, count);
                } else if (inflater.needsInput()) {
                    break;
                }
            }

            return baos.toByteArray();
        } catch (java.util.zip.DataFormatException e) {
            throw new IOException("解压数据失败: " + e.getMessage(), e);
        } finally {
            inflater.end();
        }
    }

    // ========== UI 刷新 ==========

    private void refreshUIAfterImport() {
        try {
            burp.BurpExtender.refreshUIData();
            BurpExtender.printOutput("[+] 界面数据刷新成功");
        } catch (Exception e) {
            BurpExtender.printError("[!] 刷新界面数据时出错: " + e.getMessage());
        }
    }

    // ========== 大端序读取工具 ==========

    private static int readUint16BE(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 8) | (buf[offset + 1] & 0xFF);
    }

    private static int readUint32BE(byte[] buf, int offset) {
        return ((buf[offset] & 0xFF) << 24) | ((buf[offset + 1] & 0xFF) << 16)
                | ((buf[offset + 2] & 0xFF) << 8) | (buf[offset + 3] & 0xFF);
    }

    private static long readUint64BE(byte[] buf, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (buf[offset + i] & 0xFF);
        }
        return value;
    }
}
