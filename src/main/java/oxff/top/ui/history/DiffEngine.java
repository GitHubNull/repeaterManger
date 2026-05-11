package oxff.top.ui.history;

import oxff.top.privilege.LevenshteinCalculator;

import java.util.ArrayList;
import java.util.List;

/**
 * Diff引擎 - 无状态工具类
 * 提供行级差异（Myers diff算法）和字节级差异（hex dump）计算
 */
public class DiffEngine {

    /**
     * 差异类型枚举
     */
    public enum DiffType {
        UNCHANGED,   // 未变化
        ADDED,       // 新增行
        REMOVED,     // 删除行
        CHANGED      // 修改行（内容有变化但行号对齐）
    }

    /**
     * 行级差异结果
     */
    public static class DiffLine {
        private final int lineNumber;
        private final String lineText;
        private final DiffType diffType;

        public DiffLine(int lineNumber, String lineText, DiffType diffType) {
            this.lineNumber = lineNumber;
            this.lineText = lineText;
            this.diffType = diffType;
        }

        public int getLineNumber() { return lineNumber; }
        public String getLineText() { return lineText; }
        public DiffType getDiffType() { return diffType; }
    }

    /**
     * 字节级差异结果（hex格式）
     */
    public static class DiffSegment {
        private final int offset;
        private final String hexData;
        private final String asciiData;
        private final DiffType diffType;

        public DiffSegment(int offset, String hexData, String asciiData, DiffType diffType) {
            this.offset = offset;
            this.hexData = hexData;
            this.asciiData = asciiData;
            this.diffType = diffType;
        }

        public int getOffset() { return offset; }
        public String getHexData() { return hexData; }
        public String getAsciiData() { return asciiData; }
        public DiffType getDiffType() { return diffType; }
    }

    /**
     * 计算行级差异（使用Myers diff算法的简化实现）
     *
     * @param text1 原始文本
     * @param text2 修改文本
     * @return 逐行差异列表
     */
    public static List<DiffLine> computeLineDiff(String text1, String text2) {
        String[] lines1 = text1.split("\r\n|\n", -1);
        String[] lines2 = text2.split("\r\n|\n", -1);

        // 使用LCS算法计算最长公共子序列
        List<int[]> lcsIndices = computeLCS(lines1, lines2);

        List<DiffLine> result = new ArrayList<>();
        int idx1 = 0, idx2 = 0;

        for (int[] lcsPair : lcsIndices) {
            int lcsIdx1 = lcsPair[0];
            int lcsIdx2 = lcsPair[1];

            // lines1中在LCS之前的行：被删除
            while (idx1 < lcsIdx1) {
                result.add(new DiffLine(idx1 + 1, lines1[idx1], DiffType.REMOVED));
                idx1++;
            }
            // lines2中在LCS之前的行：新增
            while (idx2 < lcsIdx2) {
                result.add(new DiffLine(idx2 + 1, lines2[idx2], DiffType.ADDED));
                idx2++;
            }
            // LCS行：未变化
            result.add(new DiffLine(idx1 + 1, lines1[idx1], DiffType.UNCHANGED));
            idx1++;
            idx2++;
        }

        // 处理剩余行
        while (idx1 < lines1.length) {
            result.add(new DiffLine(idx1 + 1, lines1[idx1], DiffType.REMOVED));
            idx1++;
        }
        while (idx2 < lines2.length) {
            result.add(new DiffLine(idx2 + 1, lines2[idx2], DiffType.ADDED));
            idx2++;
        }

        return result;
    }

    /**
     * 计算字节级差异（hex dump格式比对）
     *
     * @param data1 原始字节
     * @param data2 修改字节
     * @return hex格式差异段列表
     */
    public static List<DiffSegment> computeByteDiff(byte[] data1, byte[] data2) {
        List<String> hexLines1 = generateHexDump(data1);
        List<String> hexLines2 = generateHexDump(data2);

        // 对hex行做行级diff
        String[] lines1Arr = hexLines1.toArray(new String[0]);
        String[] lines2Arr = hexLines2.toArray(new String[0]);

        List<int[]> lcsIndices = computeLCS(lines1Arr, lines2Arr);

        List<DiffSegment> result = new ArrayList<>();
        int idx1 = 0, idx2 = 0;

        for (int[] lcsPair : lcsIndices) {
            int lcsIdx1 = lcsPair[0];
            int lcsIdx2 = lcsPair[1];

            while (idx1 < lcsIdx1) {
                result.add(parseHexLine(hexLines1.get(idx1), DiffType.REMOVED));
                idx1++;
            }
            while (idx2 < lcsIdx2) {
                result.add(parseHexLine(hexLines2.get(idx2), DiffType.ADDED));
                idx2++;
            }
            result.add(parseHexLine(hexLines1.get(idx1), DiffType.UNCHANGED));
            idx1++;
            idx2++;
        }

        while (idx1 < hexLines1.size()) {
            result.add(parseHexLine(hexLines1.get(idx1), DiffType.REMOVED));
            idx1++;
        }
        while (idx2 < hexLines2.size()) {
            result.add(parseHexLine(hexLines2.get(idx2), DiffType.ADDED));
            idx2++;
        }

        return result;
    }

    /**
     * 计算相似度（复用LevenshteinCalculator）
     */
    public static double computeSimilarity(String text1, String text2) {
        return LevenshteinCalculator.similarity(text1, text2);
    }

    // ==================== LCS算法 ====================

    /**
     * 计算最长公共子序列的索引对
     * 返回List<int[]>，每个int[]为{lines1_index, lines2_index}
     */
    private static List<int[]> computeLCS(String[] lines1, String[] lines2) {
        int m = lines1.length;
        int n = lines2.length;

        // DP表：记录LCS长度
        int[][] dp = new int[m + 1][n + 1];

        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (lines1[i - 1].equals(lines2[j - 1])) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        // 回溯获取LCS索引对
        List<int[]> lcsIndices = new ArrayList<>();
        int i = m, j = n;
        while (i > 0 && j > 0) {
            if (lines1[i - 1].equals(lines2[j - 1])) {
                lcsIndices.add(0, new int[]{i - 1, j - 1});
                i--;
                j--;
            } else if (dp[i - 1][j] >= dp[i][j - 1]) {
                i--;
            } else {
                j--;
            }
        }

        return lcsIndices;
    }

    // ==================== Hex Dump ====================

    /**
     * 生成hex dump格式行列表
     * 每行格式: "OFFSET  HEX_BYTES  ASCII"
     * 每行16字节
     */
    public static List<String> generateHexDump(byte[] data) {
        List<String> lines = new ArrayList<>();
        int bytesPerLine = 16;

        for (int offset = 0; offset < data.length; offset += bytesPerLine) {
            int lineLen = Math.min(bytesPerLine, data.length - offset);

            StringBuilder hexPart = new StringBuilder();
            StringBuilder asciiPart = new StringBuilder();

            for (int i = 0; i < lineLen; i++) {
                byte b = data[offset + i];
                hexPart.append(String.format("%02X", b));
                if (i < lineLen - 1) hexPart.append(" ");

                char c = (b >= 32 && b <= 126) ? (char) b : '.';
                asciiPart.append(c);
            }

            // 补齐hex部分的空位（不足16字节时）
            if (lineLen < bytesPerLine) {
                for (int i = lineLen; i < bytesPerLine; i++) {
                    hexPart.append("   ");
                }
            }

            lines.add(String.format("%08X  %s  %s", offset, hexPart, asciiPart));
        }

        return lines;
    }

    /**
     * 从hex dump行解析为DiffSegment
     */
    private static DiffSegment parseHexLine(String hexLine, DiffType diffType) {
        // 格式: "OFFSET  HEX_BYTES  ASCII"
        String[] parts = hexLine.split("  ", 3);
        int offset = parts.length > 0 ? (int) Long.parseLong(parts[0].trim(), 16) : 0;
        String hexData = parts.length > 1 ? parts[1].trim() : "";
        String asciiData = parts.length > 2 ? parts[2].trim() : "";

        return new DiffSegment(offset, hexData, asciiData, diffType);
    }
}