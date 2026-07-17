package org.oxff.repeater.privilege.report;

import org.oxff.repeater.io.ErmCryptoHelper;
import org.oxff.repeater.logging.LogManager;
import java.awt.Component;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * .ermr 容器格式写入器
 * 支持加密+压缩、仅压缩、明文三种输出模式
 *
 * 容器格式规范 (.ermr v1):
 * [HEADER - 变长, 最少24字节+文件名长度]
 *   Magic:           4B - 0x89 0x45 0x52 0x52 (高位+ERR)
 *   Format Version:  2B - 0x0001 (big-endian)
 *   Flags:           4B - bit0:加密, bit1:压缩 (big-endian)
 *   Original Filename: 2B长度前缀 + 变长UTF-8字节
 *   Original Size:   8B - 原始未压缩未加密大小 (big-endian)
 *   Header CRC:      4B - CRC32(前面所有header字节)
 *
 * [CRYPTO HEADER - 64B, 仅加密模式]
 *   Salt: 16B + IV: 16B + HMAC: 32B
 *
 * [DATA - 变长]
 *   处理流程: 加密+压缩 -> 先DEFLATE压缩再AES-CBC+HMAC加密
 *            仅压缩 -> DEFLATE压缩
 *
 * [FOOTER - 12B]
 *   Magic: "ERRE" 4B
 *   Data CRC: 4B - CRC32(DATA段)
 *   Footer CRC: 4B - CRC32(footer前8字节)
 */
public class ReportContainerWriter {

    /** 容器头魔法数字: 0x89 ERR */
    private static final byte[] MAGIC_HEADER = {(byte) 0x89, 0x45, 0x52, 0x52};
    /** 容器尾魔法数字: ERRE */
    private static final byte[] MAGIC_FOOTER = {0x45, 0x52, 0x52, 0x45};
    /** 格式版本 */
    private static final int FORMAT_VERSION = 1;
    /** 标志位: 加密 */
    private static final int FLAG_ENCRYPTED = 0x00000001;
    /** 标志位: 压缩 */
    private static final int FLAG_COMPRESSED = 0x00000002;
    /** 压缩阈值: 小于此值不压缩 */
    private static final int STORED_THRESHOLD = 4096;
    /** 缓冲区大小 */
    private static final int BUFFER_SIZE = 8192;

    /** 输出模式 */
    public enum EncryptionMode {
        /** 加密+压缩 (默认) */
        ENCRYPTED_COMPRESSED,
        /** 仅压缩 */
        COMPRESSED_ONLY,
        /** 明文 (不使用容器) */
        PLAIN
    }

    /**
     * 写入 .ermr 容器
     *
     * @param outputFile      输出文件
     * @param reportContent   报告内容字节
     * @param originalFilename 原始文件名 (如 "privilege_test_report.html")
     * @param mode            输出模式
     * @param parent          父组件 (用于密码对话框)
     * @return true=成功, false=用户取消或失败
     */
    public boolean write(File outputFile, byte[] reportContent, String originalFilename,
                         EncryptionMode mode, Component parent) {
        if (mode == EncryptionMode.PLAIN) {
            throw new IllegalArgumentException("PLAIN mode should not use container writer");
        }

        // 加密模式: 弹出密码对话框
        char[] password = null;
        if (mode == EncryptionMode.ENCRYPTED_COMPRESSED) {
            password = ErmCryptoHelper.promptPasswordForExport(parent);
            if (password == null) {
                return false; // 用户取消
            }
        }

        try {
            byte[] dataToWrite = reportContent;
            int flags = 0;

            // 步骤1: 压缩
            if (reportContent.length >= STORED_THRESHOLD) {
                byte[] compressedData = compressData(reportContent);
                if (compressedData.length < reportContent.length) {
                    dataToWrite = compressedData;
                    flags |= FLAG_COMPRESSED;
                }
            }

            // 步骤2: 加密 (压缩后)
            byte[] salt = null;
            byte[] iv = null;
            byte[] hmac = null;
            if (mode == EncryptionMode.ENCRYPTED_COMPRESSED) {
                flags |= FLAG_ENCRYPTED;

                salt = ErmCryptoHelper.generateSalt();
                ErmCryptoHelper.KeyPair keyPair = ErmCryptoHelper.deriveKeys(password, salt);

                ErmCryptoHelper.EncryptionResult encResult =
                        ErmCryptoHelper.encrypt(dataToWrite, keyPair.aesKey, keyPair.hmacKey);

                iv = encResult.iv;
                hmac = encResult.hmac;
                dataToWrite = encResult.ciphertext;
            }

            // 步骤3: 计算 Data CRC
            CRC32 dataCrc = new CRC32();
            dataCrc.update(dataToWrite);
            long dataCrcValue = dataCrc.getValue();

            // 步骤4: 写入文件
            writeContainerFile(outputFile, originalFilename, reportContent.length,
                    flags, salt, iv, hmac, dataToWrite, dataCrcValue);

            return true;
        } catch (Exception e) {
            // 写入失败: 删除部分文件
            if (outputFile.exists()) {
                outputFile.delete();
            }
            throw new RuntimeException("Failed to write .ermr container: " + e.getMessage(), e);
        } finally {
            if (password != null) {
                ErmCryptoHelper.clearPassword(password);
            }
        }
    }

    /**
     * 将目录打包为 ZIP，再写入 .ermr 容器
     * 用于多文件 HTML 报告的加密导出
     *
     * @param outputFile 输出 .ermr 文件
     * @param reportDir  报告目录（将被 ZIP 打包）
     * @param mode       输出模式
     * @param parent     父组件 (用于密码对话框)
     * @return true=成功, false=用户取消或失败
     */
    public boolean write(File outputFile, File reportDir, EncryptionMode mode, Component parent) {
        try {
            // ZIP 打包整个目录
            ByteArrayOutputStream zipBaos = new ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(zipBaos)) {
                java.nio.file.Path dirPath = reportDir.toPath();
                Files.walk(dirPath)
                        .filter(p -> !Files.isDirectory(p))
                        .forEach(p -> {
                            try {
                                String entryName = dirPath.relativize(p).toString().replace("\\", "/");
                                zos.putNextEntry(new ZipEntry(entryName));
                                Files.copy(p, zos);
                                zos.closeEntry();
                            } catch (IOException e) {
                                LogManager.getInstance().printError("[!] ZIP打包文件失败: " + p + " - " + e.getMessage());
                            }
                        });
            }

            byte[] zipBytes = zipBaos.toByteArray();
            String zipFilename = reportDir.getName() + ".zip";

            // 委托给字节模式写入
            return write(outputFile, zipBytes, zipFilename, mode, parent);
        } catch (Exception e) {
            if (outputFile.exists()) {
                outputFile.delete();
            }
            throw new RuntimeException("Failed to write .ermr container from directory: " + e.getMessage(), e);
        }
    }

    /**
     * 压缩数据 (DEFLATE)
     * 复用 ErmArchiveWriter 的压缩模式
     */
    private byte[] compressData(byte[] input) {
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);
        try {
            deflater.setInput(input);
            deflater.finish();

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length / 4);
            byte[] buffer = new byte[BUFFER_SIZE];

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

    /**
     * 写入容器文件
     */
    private void writeContainerFile(File outputFile, String originalFilename, long originalSize,
                                     int flags, byte[] salt, byte[] iv, byte[] hmac,
                                     byte[] data, long dataCrcValue) throws Exception {
        // 先在内存中构建 header
        byte[] filenameBytes = originalFilename.getBytes(StandardCharsets.UTF_8);

        // 构建 header (不含 CRC)
        ByteArrayOutputStream headerBaos = new ByteArrayOutputStream();
        // Magic
        headerBaos.write(MAGIC_HEADER);
        // Format Version
        headerBaos.write(ByteBuffer.allocate(2).putShort((short) FORMAT_VERSION).array());
        // Flags
        headerBaos.write(ByteBuffer.allocate(4).putInt(flags).array());
        // Original Filename: 2B length + UTF-8 bytes
        headerBaos.write(ByteBuffer.allocate(2).putShort((short) filenameBytes.length).array());
        headerBaos.write(filenameBytes);
        // Original Size
        headerBaos.write(ByteBuffer.allocate(8).putLong(originalSize).array());

        byte[] headerBytes = headerBaos.toByteArray();

        // 计算 Header CRC
        CRC32 headerCrc = new CRC32();
        headerCrc.update(headerBytes);
        long headerCrcValue = headerCrc.getValue();

        // 构建 Footer
        CRC32 footerCrc = new CRC32();
        ByteBuffer footerBuf = ByteBuffer.allocate(12);
        footerBuf.put(MAGIC_FOOTER);
        footerBuf.putInt((int) dataCrcValue);
        byte[] footerPrefix = new byte[8];
        footerBuf.position(0);
        footerBuf.get(footerPrefix);
        footerCrc.update(footerPrefix);
        footerBuf.putInt((int) footerCrc.getValue());
        byte[] footerBytes = footerBuf.array();

        // 写入文件
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            // Header
            fos.write(headerBytes);
            // Header CRC
            fos.write(ByteBuffer.allocate(4).putInt((int) headerCrcValue).array());

            // Crypto Header (仅加密模式)
            if ((flags & FLAG_ENCRYPTED) != 0 && salt != null) {
                fos.write(salt);   // 16 bytes
                fos.write(iv);     // 16 bytes
                fos.write(hmac);   // 32 bytes
            }

            // Data
            fos.write(data);

            // Footer
            fos.write(footerBytes);
        }
    }
}
