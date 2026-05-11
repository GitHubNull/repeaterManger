package oxff.top.io;

import burp.BurpExtender;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import oxff.top.db.DatabaseManager;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * ERM 存档导出器
 * 将当前会话（数据库 + blobs）打包为 .erm 存档文件
 * 支持可选的 AES-256-CBC + HMAC-SHA256 加密
 */
public class ErmArchiveWriter {

    private final DatabaseManager dbManager;

    public ErmArchiveWriter() {
        this.dbManager = DatabaseManager.getInstance();
    }

    /**
     * 导出当前数据库到 ERM 存档文件（UI入口）
     *
     * @param parent 父组件
     * @param encrypted 是否加密
     */
    public boolean export(Component parent, boolean encrypted) {
        try {
            BurpExtender.printOutput("[+] 开始ERM存档导出过程" + (encrypted ? "（加密模式）" : ""));

            // 1. 选择文件
            File selectedFile = oxff.top.utils.FileChooserHelper.showSaveDialog(
                    oxff.top.utils.FileChooserHelper.OP_ERM_EXPORT, "导出ERM存档", parent,
                    new File(oxff.top.config.DatabaseConfig.generateSessionDirectoryName() + ".erm"),
                    new FileNameExtensionFilter("ERM存档 (*.erm)", "erm"));

            if (selectedFile == null) {
                return false;
            }

            File outputFile = selectedFile;

            // 确保扩展名
            String name = outputFile.getName().toLowerCase();
            if (!name.endsWith(".erm")) {
                outputFile = new File(outputFile.getAbsolutePath() + ".erm");
            }

            // 确认覆盖
            if (outputFile.exists()) {
                int overwrite = JOptionPane.showConfirmDialog(
                        parent, "文件已存在，是否覆盖？", "确认覆盖", JOptionPane.YES_NO_OPTION);
                if (overwrite != JOptionPane.YES_OPTION) {
                    return false;
                }
            }

            // 2. 加密时获取密码
            char[] password = null;
            if (encrypted) {
                password = ErmCryptoHelper.promptPasswordForExport(parent);
                if (password == null) {
                    return false;
                }
            }

            // 3. 获取源数据库路径
            String currentDbPath = dbManager.getCurrentDatabasePath();
            if (currentDbPath == null) {
                currentDbPath = dbManager.getConfig().getDatabasePath();
            }
            File sourceDb = new File(currentDbPath);

            // 如果源文件不存在，尝试初始化
            if (!sourceDb.exists()) {
                if (!dbManager.initialize()) {
                    throw new IOException("无法初始化数据库");
                }
                try (Connection conn = dbManager.getConnection();
                     Statement stmt = conn.createStatement()) {
                    stmt.executeQuery("SELECT 1");
                } catch (SQLException e) {
                    throw new IOException("创建数据库文件失败: " + e.getMessage());
                }
                currentDbPath = dbManager.getCurrentDatabasePath();
                sourceDb = new File(currentDbPath);
            }

            if (!sourceDb.exists()) {
                throw new IOException("源数据库文件不存在");
            }

            // 4. 收集 blob 文件列表
            File sourceDir = sourceDb.getParentFile();
            File sourceBlobs = new File(sourceDir, "blobs");
            List<File> blobFiles = new ArrayList<>();
            if (sourceBlobs.exists() && sourceBlobs.isDirectory()) {
                collectBlobFiles(sourceBlobs, sourceBlobs, blobFiles);
                Collections.sort(blobFiles);
            }

            // 5. 执行导出
            try {
                doExport(outputFile, sourceDb, sourceDir, blobFiles, encrypted, password);
            } finally {
                ErmCryptoHelper.clearPassword(password);
            }

            BurpExtender.printOutput("[+] ERM存档导出成功: " + outputFile.getAbsolutePath());
            JOptionPane.showMessageDialog(parent,
                    "ERM存档导出成功！\n文件: " + outputFile.getAbsolutePath()
                            + "\n条目数: " + (1 + blobFiles.size()),
                    "导出成功", JOptionPane.INFORMATION_MESSAGE);
            return true;

        } catch (Exception e) {
            BurpExtender.printError("[!] 导出ERM存档失败: " + e.getMessage());
            JOptionPane.showMessageDialog(parent,
                    "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    /**
     * 执行实际的导出操作
     */
    private void doExport(File outputFile, File sourceDb, File sourceDir,
                          List<File> blobFiles, boolean encrypted, char[] password) throws Exception {
        int entryCount = 1 + blobFiles.size() + 1; // db + blobs + manifest
        int schemaVersion = getSchemaVersion();

        if (encrypted) {
            doExportEncrypted(outputFile, sourceDb, sourceDir, blobFiles,
                    entryCount, schemaVersion, password);
        } else {
            doExportPlaintext(outputFile, sourceDb, sourceDir, blobFiles,
                    entryCount, schemaVersion);
        }
    }

    /**
     * 未加密模式导出
     */
    private void doExportPlaintext(File outputFile, File sourceDb, File sourceDir,
                                    List<File> blobFiles, int entryCount,
                                    int schemaVersion) throws Exception {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(outputFile, "rw");
            raf.setLength(0);

            // 写入占位头部
            writeHeader(raf, entryCount, 0, schemaVersion, false);

            // 写入数据库条目
            writeEntryFromFile(raf, ErmFormatConstants.DB_ENTRY_PATH, sourceDb,
                    ErmFormatConstants.COMPRESSION_DEFLATED);

            // 写入 blob 条目
            for (File blobFile : blobFiles) {
                String relativePath = getRelativePath(sourceDir, blobFile);
                byte compression = blobFile.length() > ErmFormatConstants.STORED_THRESHOLD
                        ? ErmFormatConstants.COMPRESSION_DEFLATED
                        : ErmFormatConstants.COMPRESSION_STORED;
                writeEntryFromFile(raf, relativePath, blobFile, compression);
            }

            // 记录 manifest 偏移
            long manifestOffset = raf.getFilePointer();

            // 写入 manifest 条目
            byte[] manifestData = buildManifestJson(entryCount, blobFiles.size(),
                    schemaVersion, false);
            writeEntryFromBytes(raf, ErmFormatConstants.MANIFEST_ENTRY_PATH, manifestData,
                    ErmFormatConstants.COMPRESSION_DEFLATED);

            // 写入尾部
            writeFooter(raf);

            // 回写头部字段
            patchHeader(raf, manifestOffset);

        } catch (Exception e) {
            // 失败时删除部分写入的文件
            if (outputFile.exists()) {
                outputFile.delete();
            }
            throw e;
        } finally {
            if (raf != null) {
                try { raf.close(); } catch (IOException ignored) {}
            }
        }
    }

    /**
     * 加密模式导出
     */
    private void doExportEncrypted(File outputFile, File sourceDb, File sourceDir,
                                    List<File> blobFiles, int entryCount,
                                    int schemaVersion, char[] password) throws Exception {
        RandomAccessFile raf = null;
        try {
            raf = new RandomAccessFile(outputFile, "rw");
            raf.setLength(0);

            // 写入占位头部（标记加密）
            writeHeader(raf, entryCount, 0, schemaVersion, true);

            // 将所有数据条目组装到缓冲区
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            // 写入数据库条目到缓冲区
            writeEntryToStream(baos, ErmFormatConstants.DB_ENTRY_PATH, sourceDb,
                    ErmFormatConstants.COMPRESSION_DEFLATED);

            // 写入 blob 条目到缓冲区
            for (File blobFile : blobFiles) {
                String relativePath = getRelativePath(sourceDir, blobFile);
                byte compression = blobFile.length() > ErmFormatConstants.STORED_THRESHOLD
                        ? ErmFormatConstants.COMPRESSION_DEFLATED
                        : ErmFormatConstants.COMPRESSION_STORED;
                writeEntryToStream(baos, relativePath, blobFile, compression);
            }

            // 记录 manifest 偏移（在缓冲区中的位置）
            long manifestOffset = baos.size();

            // 写入 manifest 条目到缓冲区
            byte[] manifestData = buildManifestJson(entryCount, blobFiles.size(),
                    schemaVersion, true);
            writeEntryBytesToStream(baos, ErmFormatConstants.MANIFEST_ENTRY_PATH, manifestData,
                    ErmFormatConstants.COMPRESSION_DEFLATED);

            // 加密整个缓冲区
            byte[] plaintext = baos.toByteArray();
            baos = null; // 释放内存

            // 生成盐值并派生密钥
            byte[] salt = ErmCryptoHelper.generateSalt();
            ErmCryptoHelper.KeyPair keyPair = ErmCryptoHelper.deriveKeys(password, salt);

            // Encrypt-then-MAC
            ErmCryptoHelper.EncryptionResult encResult = ErmCryptoHelper.encrypt(
                    plaintext, keyPair.aesKey, keyPair.hmacKey);
            Arrays.fill(plaintext, (byte) 0); // 清理明文

            // 写入加密头
            raf.write(salt);
            raf.write(encResult.iv);
            raf.write(encResult.hmac);

            // 写入加密数据
            raf.write(encResult.ciphertext);

            // 写入尾部
            writeFooter(raf);

            // 回写头部字段
            patchHeader(raf, manifestOffset);

        } catch (Exception e) {
            if (outputFile.exists()) {
                outputFile.delete();
            }
            throw e;
        } finally {
            if (raf != null) {
                try { raf.close(); } catch (IOException ignored) {}
            }
        }
    }

    // ========== 文件头写入 ==========

    /**
     * 写入 32 字节文件头（占位，部分字段稍后回填）
     */
    private void writeHeader(RandomAccessFile raf, int entryCount, long manifestOffset,
                              int schemaVersion, boolean encrypted) throws IOException {
        byte[] header = new byte[ErmFormatConstants.HEADER_SIZE];
        int pos = 0;

        // 魔法数字 (4 bytes)
        System.arraycopy(ErmFormatConstants.MAGIC_HEADER, 0, header, pos, 4);
        pos += 4;

        // format_version (2 bytes, big-endian)
        header[pos++] = (byte) ((ErmFormatConstants.FORMAT_VERSION >> 8) & 0xFF);
        header[pos++] = (byte) (ErmFormatConstants.FORMAT_VERSION & 0xFF);

        // flags (4 bytes, big-endian)
        int flags = encrypted ? ErmFormatConstants.FLAG_ENCRYPTED : 0;
        header[pos++] = (byte) ((flags >> 24) & 0xFF);
        header[pos++] = (byte) ((flags >> 16) & 0xFF);
        header[pos++] = (byte) ((flags >> 8) & 0xFF);
        header[pos++] = (byte) (flags & 0xFF);

        // entry_count (4 bytes, big-endian)
        header[pos++] = (byte) ((entryCount >> 24) & 0xFF);
        header[pos++] = (byte) ((entryCount >> 16) & 0xFF);
        header[pos++] = (byte) ((entryCount >> 8) & 0xFF);
        header[pos++] = (byte) (entryCount & 0xFF);

        // manifest_offset (8 bytes, big-endian) - 占位
        for (int i = 7; i >= 0; i--) {
            header[pos++] = (byte) ((manifestOffset >> (i * 8)) & 0xFF);
        }

        // schema_version (4 bytes, big-endian)
        header[pos++] = (byte) ((schemaVersion >> 24) & 0xFF);
        header[pos++] = (byte) ((schemaVersion >> 16) & 0xFF);
        header[pos++] = (byte) ((schemaVersion >> 8) & 0xFF);
        header[pos++] = (byte) (schemaVersion & 0xFF);

        // header_size (2 bytes, big-endian)
        header[pos++] = (byte) ((ErmFormatConstants.HEADER_SIZE >> 8) & 0xFF);
        header[pos++] = (byte) (ErmFormatConstants.HEADER_SIZE & 0xFF);

        // header_crc (4 bytes) - 占位，稍后计算
        pos += 4;

        raf.write(header);
    }

    /**
     * 回填头部字段（manifest_offset、header_crc）
     */
    private void patchHeader(RandomAccessFile raf, long manifestOffset) throws IOException {
        // 写入 manifest_offset (offset 14, 8 bytes)
        raf.seek(14);
        for (int i = 7; i >= 0; i--) {
            raf.write((byte) ((manifestOffset >> (i * 8)) & 0xFF));
        }

        // 计算并写入 header_crc (offset 28, 4 bytes)
        raf.seek(0);
        byte[] headerBytes = new byte[ErmFormatConstants.HEADER_SIZE];
        raf.readFully(headerBytes);

        CRC32 crc32 = new CRC32();
        crc32.update(headerBytes, 0, 28); // 字节 0-27
        int headerCrc = (int) crc32.getValue();

        raf.seek(28);
        raf.write((headerCrc >> 24) & 0xFF);
        raf.write((headerCrc >> 16) & 0xFF);
        raf.write((headerCrc >> 8) & 0xFF);
        raf.write(headerCrc & 0xFF);
    }

    // ========== 文件尾写入 ==========

    /**
     * 写入 16 字节文件尾
     */
    private void writeFooter(RandomAccessFile raf) throws IOException {
        // 计算 data_crc: 头部之后到当前位置的所有字节
        long currentPos = raf.getFilePointer();
        long dataStart = ErmFormatConstants.HEADER_SIZE;
        long dataLength = currentPos - dataStart;

        CRC32 dataCrc = new CRC32();
        if (dataLength > 0) {
            long savedPos = raf.getFilePointer();
            raf.seek(dataStart);
            byte[] buffer = new byte[ErmFormatConstants.BUFFER_SIZE];
            long remaining = dataLength;
            while (remaining > 0) {
                int toRead = (int) Math.min(buffer.length, remaining);
                int read = raf.read(buffer, 0, toRead);
                if (read <= 0) break;
                dataCrc.update(buffer, 0, read);
                remaining -= read;
            }
            raf.seek(savedPos);
        }

        byte[] footer = new byte[ErmFormatConstants.FOOTER_SIZE];
        int pos = 0;

        // 魔法数字 (4 bytes)
        System.arraycopy(ErmFormatConstants.MAGIC_FOOTER, 0, footer, pos, 4);
        pos += 4;

        // data_crc (4 bytes, big-endian)
        int dataCrcValue = (int) dataCrc.getValue();
        footer[pos++] = (byte) ((dataCrcValue >> 24) & 0xFF);
        footer[pos++] = (byte) ((dataCrcValue >> 16) & 0xFF);
        footer[pos++] = (byte) ((dataCrcValue >> 8) & 0xFF);
        footer[pos++] = (byte) (dataCrcValue & 0xFF);

        // footer_crc (4 bytes) - 占位
        pos += 4;

        // reserved (4 bytes)
        pos += 4;

        // 计算 footer_crc（字节 0-11）
        CRC32 footerCrc = new CRC32();
        footerCrc.update(footer, 0, 12);
        int footerCrcValue = (int) footerCrc.getValue();
        footer[8] = (byte) ((footerCrcValue >> 24) & 0xFF);
        footer[9] = (byte) ((footerCrcValue >> 16) & 0xFF);
        footer[10] = (byte) ((footerCrcValue >> 8) & 0xFF);
        footer[11] = (byte) (footerCrcValue & 0xFF);

        raf.write(footer);
    }

    // ========== 条目写入（到 RandomAccessFile） ==========

    /**
     * 从文件写入一个数据条目到 RandomAccessFile
     */
    private void writeEntryFromFile(RandomAccessFile raf, String entryPath, File sourceFile,
                                     byte compressionMethod) throws IOException {
        byte[] fileData = Files.readAllBytes(sourceFile.toPath());
        writeEntryFromBytes(raf, entryPath, fileData, compressionMethod);
    }

    /**
     * 从字节数组写入一个数据条目到 RandomAccessFile
     */
    private void writeEntryFromBytes(RandomAccessFile raf, String entryPath, byte[] data,
                                      byte compressionMethod) throws IOException {
        byte[] pathBytes = entryPath.getBytes(StandardCharsets.UTF_8);
        int pathLength = pathBytes.length;

        // 计算原始数据的 CRC32
        CRC32 crc32 = new CRC32();
        crc32.update(data);
        int entryCrc = (int) crc32.getValue();
        long uncompressedSize = data.length;

        // 压缩数据
        byte[] compressedData;
        if (compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED) {
            compressedData = compressData(data);
        } else {
            compressedData = data;
        }
        long compressedSize = compressedData.length;

        // 如果压缩后更大，改用 STORED
        if (compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED
                && compressedSize >= uncompressedSize) {
            compressionMethod = ErmFormatConstants.COMPRESSION_STORED;
            compressedData = data;
            compressedSize = data.length;
        }

        // 写入条目头
        // path_length (2 bytes, big-endian)
        raf.write((pathLength >> 8) & 0xFF);
        raf.write(pathLength & 0xFF);

        // path
        raf.write(pathBytes);

        // compression_method (1 byte)
        raf.write(compressionMethod);

        // compressed_size (8 bytes, big-endian)
        for (int i = 7; i >= 0; i--) {
            raf.write((byte) ((compressedSize >> (i * 8)) & 0xFF));
        }

        // uncompressed_size (8 bytes, big-endian)
        for (int i = 7; i >= 0; i--) {
            raf.write((byte) ((uncompressedSize >> (i * 8)) & 0xFF));
        }

        // entry_crc (4 bytes, big-endian)
        raf.write((entryCrc >> 24) & 0xFF);
        raf.write((entryCrc >> 16) & 0xFF);
        raf.write((entryCrc >> 8) & 0xFF);
        raf.write(entryCrc & 0xFF);

        // data
        raf.write(compressedData);
    }

    // ========== 条目写入（到 ByteArrayOutputStream，用于加密模式） ==========

    /**
     * 从文件写入一个数据条目到流（加密模式使用）
     */
    private void writeEntryToStream(ByteArrayOutputStream baos, String entryPath, File sourceFile,
                                     byte compressionMethod) throws IOException {
        byte[] fileData = Files.readAllBytes(sourceFile.toPath());
        writeEntryBytesToStream(baos, entryPath, fileData, compressionMethod);
    }

    /**
     * 从字节数组写入一个数据条目到流（加密模式使用）
     */
    private void writeEntryBytesToStream(ByteArrayOutputStream baos, String entryPath, byte[] data,
                                          byte compressionMethod) throws IOException {
        // 与 writeEntryFromBytes 逻辑相同，但写入 baos
        byte[] pathBytes = entryPath.getBytes(StandardCharsets.UTF_8);
        int pathLength = pathBytes.length;

        CRC32 crc32 = new CRC32();
        crc32.update(data);
        int entryCrc = (int) crc32.getValue();
        long uncompressedSize = data.length;

        byte[] compressedData;
        if (compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED) {
            compressedData = compressData(data);
        } else {
            compressedData = data;
        }
        long compressedSize = compressedData.length;

        if (compressionMethod == ErmFormatConstants.COMPRESSION_DEFLATED
                && compressedSize >= uncompressedSize) {
            compressionMethod = ErmFormatConstants.COMPRESSION_STORED;
            compressedData = data;
            compressedSize = data.length;
        }

        // 构建条目字节
        ByteArrayOutputStream entryBaos = new ByteArrayOutputStream();

        // path_length (2 bytes)
        entryBaos.write((pathLength >> 8) & 0xFF);
        entryBaos.write(pathLength & 0xFF);

        // path
        entryBaos.write(pathBytes);

        // compression_method
        entryBaos.write(compressionMethod);

        // compressed_size (8 bytes)
        for (int i = 7; i >= 0; i--) {
            entryBaos.write((byte) ((compressedSize >> (i * 8)) & 0xFF));
        }

        // uncompressed_size (8 bytes)
        for (int i = 7; i >= 0; i--) {
            entryBaos.write((byte) ((uncompressedSize >> (i * 8)) & 0xFF));
        }

        // entry_crc (4 bytes)
        entryBaos.write((entryCrc >> 24) & 0xFF);
        entryBaos.write((entryCrc >> 16) & 0xFF);
        entryBaos.write((entryCrc >> 8) & 0xFF);
        entryBaos.write(entryCrc & 0xFF);

        // data
        entryBaos.write(compressedData);

        baos.write(entryBaos.toByteArray());
    }

    // ========== 压缩 ==========

    /**
     * 使用 Deflater 压缩数据
     */
    private byte[] compressData(byte[] input) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        try {
            deflater.setInput(input);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length / 4);
            byte[] buffer = new byte[ErmFormatConstants.BUFFER_SIZE];

            while (!deflater.finished()) {
                int count = deflater.deflate(buffer);
                if (count > 0) {
                    baos.write(buffer, 0, count);
                }
            }

            return baos.toByteArray();
        } finally {
            deflater.end();
        }
    }

    // ========== Manifest ==========

    /**
     * 构建清单 JSON 字节数组
     */
    private byte[] buildManifestJson(int entryCount, int blobCount, int schemaVersion,
                                      boolean encrypted) {
        Map<String, Object> manifest = new HashMap<>();
        manifest.put("format_version", ErmFormatConstants.FORMAT_VERSION);
        manifest.put("app_version", getAppVersion());
        manifest.put("created_at", System.currentTimeMillis());
        manifest.put("schema_version", schemaVersion);
        manifest.put("encrypted", encrypted);
        manifest.put("db_entry", ErmFormatConstants.DB_ENTRY_PATH);
        manifest.put("blob_count", blobCount);
        manifest.put("total_entries", entryCount);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(manifest).getBytes(StandardCharsets.UTF_8);
    }

    // ========== 辅助方法 ==========

    /**
     * 收集 blobs 目录下所有文件
     */
    private void collectBlobFiles(File baseDir, File currentDir, List<File> fileList) throws IOException {
        File[] children = currentDir.listFiles();
        if (children == null) return;

        for (File child : children) {
            if (child.isDirectory()) {
                collectBlobFiles(baseDir, child, fileList);
            } else if (child.isFile() && !child.getName().startsWith(".tmp_")) {
                fileList.add(child);
            }
        }
    }

    /**
     * 获取文件相对于基础目录的路径（使用 / 分隔符）
     */
    private String getRelativePath(File baseDir, File file) {
        Path basePath = baseDir.toPath();
        Path filePath = file.toPath();
        return basePath.relativize(filePath).toString().replace('\\', '/');
    }

    /**
     * 获取当前 Schema 版本
     */
    private int getSchemaVersion() {
        try (Connection conn = dbManager.getConnection();
             java.sql.PreparedStatement ps = conn.prepareStatement(
                     "SELECT value FROM schema_meta WHERE key = 'schema_version'")) {
            java.sql.ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return Integer.parseInt(rs.getString("value"));
            }
        } catch (Exception e) {
            BurpExtender.printOutput("[*] 无法读取schema_version，使用默认值" + ErmFormatConstants.CURRENT_SCHEMA_VERSION);
        }
        return ErmFormatConstants.CURRENT_SCHEMA_VERSION;
    }

    /**
     * 获取应用版本号
     */
    private String getAppVersion() {
        String version = getClass().getPackage().getImplementationVersion();
        if (version == null) {
            version = "1.5.0";
        }
        return version;
    }

}
