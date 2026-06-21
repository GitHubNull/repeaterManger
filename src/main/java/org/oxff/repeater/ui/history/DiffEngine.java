package org.oxff.repeater.ui.history;

import org.oxff.repeater.privilege.LevenshteinCalculator;
import org.oxff.repeater.privilege.SimilarityEngine;

import java.util.ArrayList;
import java.util.List;

/**
 * Diff引擎 - 无状态工具类
 * 提供行级差异（LCS diff算法）和字节级差异（hex dump）计算
 * 支持行内字符级差异（inline diff），用于精确标记相同/不同字符串
 */
public class DiffEngine {

    /** 行内字符级差异的长度阈值，超过则降级为词级差异 */
    private static final int INLINE_DIFF_CHAR_THRESHOLD = 5000;

    /** 行配对相似度阈值，低于此值的REMOVED+ADDED不配对为CHANGED */
    private static final double PAIR_SIMILARITY_THRESHOLD = 0.3;

    /**
     * 差异类型枚举
     */
    public enum DiffType {
        UNCHANGED,   // 未变化
        ADDED,       // 新增行
        REMOVED,     // 删除行
        CHANGED      // 修改行（内容有变化但行号对齐，配对产生）
    }

    /**
     * 行内差异段类型
     */
    public enum InlineDiffType {
        MATCH,  // 匹配的字符/词
        DIFF    // 不匹配的字符/词
    }

    /**
     * 行内差异段 — 表示一行内连续的匹配或不匹配文本
     */
    public static class InlineDiffSegment {
        private final String text;
        private final InlineDiffType type;

        public InlineDiffSegment(String text, InlineDiffType type) {
            this.text = text;
            this.type = type;
        }

        public String getText() { return text; }
        public InlineDiffType getType() { return type; }
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
     * 已变更行差异结果 — 携带行内字符级差异
     * 继承 DiffLine，增加原始侧和修改侧的行内差异段
     */
    public static class ChangedDiffLine extends DiffLine {
        private final String pairedText;                        // 配对行文本（另一侧）
        private final List<InlineDiffSegment> originalInlineDiff;  // 原始侧行内差异
        private final List<InlineDiffSegment> modifiedInlineDiff;  // 修改侧行内差异

        public ChangedDiffLine(int lineNumber, String originalText, String modifiedText,
                               List<InlineDiffSegment> originalInlineDiff,
                               List<InlineDiffSegment> modifiedInlineDiff) {
            super(lineNumber, originalText, DiffType.CHANGED);
            this.pairedText = modifiedText;
            this.originalInlineDiff = originalInlineDiff;
            this.modifiedInlineDiff = modifiedInlineDiff;
        }

        public String getPairedText() { return pairedText; }
        public List<InlineDiffSegment> getOriginalInlineDiff() { return originalInlineDiff; }
        public List<InlineDiffSegment> getModifiedInlineDiff() { return modifiedInlineDiff; }
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
     * 计算行级差异（使用LCS算法 + REMOVED/ADDED行配对 → CHANGED）
     *
     * @param text1 原始文本
     * @param text2 修改文本
     * @return 逐行差异列表（含 ChangedDiffLine 用于行内差异）
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

        // 行配对：将相邻的 REMOVED+ADDED 配对为 CHANGED
        return pairChangedLines(result);
    }

    /**
     * 行配对：扫描差异列表，将相邻的 REMOVED 和 ADDED 行配对为 CHANGED
     * 使用 Levenshtein 相似度进行贪心配对
     */
    private static List<DiffLine> pairChangedLines(List<DiffLine> rawDiff) {
        List<DiffLine> result = new ArrayList<>();
        int i = 0;

        while (i < rawDiff.size()) {
            DiffLine line = rawDiff.get(i);

            if (line.getDiffType() == DiffType.REMOVED) {
                // 收集连续的 REMOVED 行
                List<DiffLine> removedBlock = new ArrayList<>();
                while (i < rawDiff.size() && rawDiff.get(i).getDiffType() == DiffType.REMOVED) {
                    removedBlock.add(rawDiff.get(i));
                    i++;
                }

                // 收集紧随的连续 ADDED 行
                List<DiffLine> addedBlock = new ArrayList<>();
                while (i < rawDiff.size() && rawDiff.get(i).getDiffType() == DiffType.ADDED) {
                    addedBlock.add(rawDiff.get(i));
                    i++;
                }

                // 贪心配对
                List<DiffLine> paired = greedyPair(removedBlock, addedBlock);
                result.addAll(paired);
            } else {
                result.add(line);
                i++;
            }
        }

        return result;
    }

    /**
     * 行内差异结果对 — 同时包含原始侧和修改侧的差异段
     */
    public static class InlineDiffResult {
        private final List<InlineDiffSegment> originalSegments;
        private final List<InlineDiffSegment> modifiedSegments;

        public InlineDiffResult(List<InlineDiffSegment> originalSegments,
                                List<InlineDiffSegment> modifiedSegments) {
            this.originalSegments = originalSegments;
            this.modifiedSegments = modifiedSegments;
        }

        public List<InlineDiffSegment> getOriginalSegments() { return originalSegments; }
        public List<InlineDiffSegment> getModifiedSegments() { return modifiedSegments; }
    }

    /**
     * 贪心配对 REMOVED 和 ADDED 行
     * 对于 1:1 的情况直接配对；对于 N:M 的情况用相似度矩阵贪心匹配
     */
    private static List<DiffLine> greedyPair(List<DiffLine> removedBlock, List<DiffLine> addedBlock) {
        List<DiffLine> result = new ArrayList<>();
        int n = removedBlock.size();
        int m = addedBlock.size();

        if (n == 0) {
            result.addAll(addedBlock);
            return result;
        }
        if (m == 0) {
            result.addAll(removedBlock);
            return result;
        }

        // 计算 N×M 相似度矩阵
        double[][] simMatrix = new double[n][m];
        for (int ri = 0; ri < n; ri++) {
            for (int ai = 0; ai < m; ai++) {
                simMatrix[ri][ai] = LevenshteinCalculator.similarity(
                    removedBlock.get(ri).getLineText(),
                    addedBlock.get(ai).getLineText());
            }
        }

        // 贪心配对：每次选相似度最高的对
        boolean[] removedUsed = new boolean[n];
        boolean[] addedUsed = new boolean[m];
        List<int[]> pairs = new ArrayList<>();

        while (true) {
            double bestSim = -1;
            int bestRi = -1, bestAi = -1;

            for (int ri = 0; ri < n; ri++) {
                if (removedUsed[ri]) continue;
                for (int ai = 0; ai < m; ai++) {
                    if (addedUsed[ai]) continue;
                    if (simMatrix[ri][ai] > bestSim) {
                        bestSim = simMatrix[ri][ai];
                        bestRi = ri;
                        bestAi = ai;
                    }
                }
            }

            if (bestSim < PAIR_SIMILARITY_THRESHOLD || bestRi < 0) break;

            pairs.add(new int[]{bestRi, bestAi});
            removedUsed[bestRi] = true;
            addedUsed[bestAi] = true;
        }

        // 按原始顺序输出
        for (int ri = 0; ri < n; ri++) {
            if (removedUsed[ri]) {
                // 找到配对的 ADDED 行
                for (int[] pair : pairs) {
                    if (pair[0] == ri) {
                        DiffLine removedLine = removedBlock.get(ri);
                        DiffLine addedLine = addedBlock.get(pair[1]);

                        // 同时计算两侧的行内字符级差异
                        InlineDiffResult inlineResult = computeInlineDiff(
                            removedLine.getLineText(), addedLine.getLineText());

                        result.add(new ChangedDiffLine(
                            removedLine.getLineNumber(),
                            removedLine.getLineText(),
                            addedLine.getLineText(),
                            inlineResult.getOriginalSegments(),
                            inlineResult.getModifiedSegments()));
                        break;
                    }
                }
            } else {
                result.add(removedBlock.get(ri));
            }
        }

        for (int ai = 0; ai < m; ai++) {
            if (!addedUsed[ai]) {
                result.add(addedBlock.get(ai));
            }
        }

        return result;
    }

    /**
     * 计算行内字符级差异（同时生成原始侧和修改侧的差异段）
     * 短文本(≤阈值): 字符级LCS；长文本: 词级LCS
     *
     * @param originalText 原始行文本
     * @param modifiedText 修改行文本
     * @return InlineDiffResult 包含两侧的差异段
     */
    public static InlineDiffResult computeInlineDiff(String originalText, String modifiedText) {
        if (originalText.isEmpty() && modifiedText.isEmpty()) {
            return new InlineDiffResult(new ArrayList<>(), new ArrayList<>());
        }
        if (originalText.isEmpty()) {
            List<InlineDiffSegment> mod = new ArrayList<>();
            mod.add(new InlineDiffSegment(modifiedText, InlineDiffType.DIFF));
            return new InlineDiffResult(new ArrayList<>(), mod);
        }
        if (modifiedText.isEmpty()) {
            List<InlineDiffSegment> orig = new ArrayList<>();
            orig.add(new InlineDiffSegment(originalText, InlineDiffType.DIFF));
            return new InlineDiffResult(orig, new ArrayList<>());
        }

        // 长文本降级为词级差异
        if (originalText.length() > INLINE_DIFF_CHAR_THRESHOLD || modifiedText.length() > INLINE_DIFF_CHAR_THRESHOLD) {
            return computeWordDiffPair(originalText, modifiedText);
        }

        // 字符级LCS
        char[] chars1 = originalText.toCharArray();
        char[] chars2 = modifiedText.toCharArray();
        int m = chars1.length;
        int n = chars2.length;

        // DP表
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (chars1[i - 1] == chars2[j - 1]) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        // 回溯生成对齐：分别标记 s1 和 s2 中哪些位置属于 LCS
        boolean[] s1InLcs = new boolean[m];
        boolean[] s2InLcs = new boolean[n];
        int i = m, j = n;
        while (i > 0 && j > 0) {
            if (chars1[i - 1] == chars2[j - 1]) {
                s1InLcs[i - 1] = true;
                s2InLcs[j - 1] = true;
                i--;
                j--;
            } else if (dp[i - 1][j] >= dp[i][j - 1]) {
                i--;
            } else {
                j--;
            }
        }

        // 根据 LCS 标记生成两侧的差异段
        List<InlineDiffSegment> origSegments = buildSegmentsFromLcsMark(chars1, s1InLcs);
        List<InlineDiffSegment> modSegments = buildSegmentsFromLcsMark(chars2, s2InLcs);

        return new InlineDiffResult(origSegments, modSegments);
    }

    /**
     * 根据LCS标记从字符数组构建差异段列表
     * LCS标记为true的字符→MATCH，false→DIFF
     */
    private static List<InlineDiffSegment> buildSegmentsFromLcsMark(char[] chars, boolean[] inLcs) {
        List<InlineDiffSegment> segments = new ArrayList<>();
        StringBuilder buf = new StringBuilder();
        InlineDiffType currentType = null;

        for (int i = 0; i < chars.length; i++) {
            InlineDiffType type = inLcs[i] ? InlineDiffType.MATCH : InlineDiffType.DIFF;
            if (currentType == null) {
                currentType = type;
                buf.append(chars[i]);
            } else if (currentType == type) {
                buf.append(chars[i]);
            } else {
                segments.add(new InlineDiffSegment(buf.toString(), currentType));
                buf = new StringBuilder();
                buf.append(chars[i]);
                currentType = type;
            }
        }
        if (buf.length() > 0 && currentType != null) {
            segments.add(new InlineDiffSegment(buf.toString(), currentType));
        }

        return segments;
    }

    /**
     * 词级差异（双侧重写） — 按非词字符分词后做LCS，同时生成两侧差异段
     */
    private static InlineDiffResult computeWordDiffPair(String s1, String s2) {
        String[] words1 = splitByWordBoundaries(s1);
        String[] words2 = splitByWordBoundaries(s2);

        List<int[]> lcsIndices = computeLCS(words1, words2);

        // 标记哪些词属于LCS
        boolean[] w1InLcs = new boolean[words1.length];
        boolean[] w2InLcs = new boolean[words2.length];
        for (int[] pair : lcsIndices) {
            w1InLcs[pair[0]] = true;
            w2InLcs[pair[1]] = true;
        }

        // 根据 LCS 标记生成两侧的差异段
        List<InlineDiffSegment> origSegments = buildSegmentsFromLcsMark(words1, w1InLcs);
        List<InlineDiffSegment> modSegments = buildSegmentsFromLcsMark(words2, w2InLcs);

        return new InlineDiffResult(origSegments, modSegments);
    }

    /**
     * 根据LCS标记从词数组构建差异段列表（词级版本）
     */
    private static List<InlineDiffSegment> buildSegmentsFromLcsMark(String[] tokens, boolean[] inLcs) {
        List<InlineDiffSegment> segments = new ArrayList<>();
        StringBuilder matchBuf = new StringBuilder();
        StringBuilder diffBuf = new StringBuilder();

        for (int i = 0; i < tokens.length; i++) {
            if (inLcs[i]) {
                if (diffBuf.length() > 0) {
                    segments.add(new InlineDiffSegment(diffBuf.toString(), InlineDiffType.DIFF));
                    diffBuf = new StringBuilder();
                }
                matchBuf.append(tokens[i]);
            } else {
                if (matchBuf.length() > 0) {
                    segments.add(new InlineDiffSegment(matchBuf.toString(), InlineDiffType.MATCH));
                    matchBuf = new StringBuilder();
                }
                diffBuf.append(tokens[i]);
            }
        }
        if (matchBuf.length() > 0) {
            segments.add(new InlineDiffSegment(matchBuf.toString(), InlineDiffType.MATCH));
        }
        if (diffBuf.length() > 0) {
            segments.add(new InlineDiffSegment(diffBuf.toString(), InlineDiffType.DIFF));
        }

        return mergeConsecutiveSegments(segments);
    }

    /**
     * 按词边界分词 — 保留分隔符作为独立token
     */
    private static String[] splitByWordBoundaries(String text) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (isWordChar(c)) {
                current.append(c);
            } else {
                if (current.length() > 0) {
                    tokens.add(current.toString());
                    current = new StringBuilder();
                }
                tokens.add(String.valueOf(c));
            }
        }
        if (current.length() > 0) {
            tokens.add(current.toString());
        }

        return tokens.toArray(new String[0]);
    }

    private static boolean isWordChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_';
    }

    /**
     * 合并相邻的同类型段
     */
    private static List<InlineDiffSegment> mergeConsecutiveSegments(List<InlineDiffSegment> segments) {
        if (segments.isEmpty()) return segments;

        List<InlineDiffSegment> merged = new ArrayList<>();
        InlineDiffSegment current = segments.get(0);

        for (int i = 1; i < segments.size(); i++) {
            InlineDiffSegment next = segments.get(i);
            if (current.getType() == next.getType()) {
                current = new InlineDiffSegment(current.getText() + next.getText(), current.getType());
            } else {
                merged.add(current);
                current = next;
            }
        }
        merged.add(current);

        return merged;
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
     * 计算相似度（使用内容感知的混合算法）
     */
    public static double computeSimilarity(String text1, String text2) {
        return SimilarityEngine.similarity(text1, text2);
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
