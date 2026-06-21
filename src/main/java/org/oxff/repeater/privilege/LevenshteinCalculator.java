package org.oxff.repeater.privilege;

/**
 * Levenshtein相似度计算器 - 无状态工具类
 * 计算两个字符串之间的Levenshtein编辑距离，并归一化为相似度比率
 *
 * 用于权限测试模式下比较不同用户会话的响应相似度
 * 相似度低于阈值（默认0.7）表示响应差异显著，可能存在越权
 */
public class LevenshteinCalculator {

    /** 大响应截断阈值（5KB），避免性能问题 */
    private static final int MAX_COMPARISON_LENGTH = 5 * 1024;

    /**
     * 计算两个字符串的归一化相似度
     *
     * @param s1 第一个字符串
     * @param s2 第二个字符串
     * @return 相似度值 0.0~1.0，1.0表示完全相同，0.0表示完全不同
     */
    public static double similarity(String s1, String s2) {
        if (s1 == null && s2 == null) return 1.0;
        if (s1 == null || s2 == null) return 0.0;
        if (s1.isEmpty() && s2.isEmpty()) return 1.0;
        if (s1.isEmpty() || s2.isEmpty()) return 0.0;
        if (s1.equals(s2)) return 1.0;

        // 截断大响应
        if (s1.length() > MAX_COMPARISON_LENGTH) {
            s1 = s1.substring(0, MAX_COMPARISON_LENGTH);
        }
        if (s2.length() > MAX_COMPARISON_LENGTH) {
            s2 = s2.substring(0, MAX_COMPARISON_LENGTH);
        }

        int distance = levenshteinDistance(s1, s2);
        int maxLen = Math.max(s1.length(), s2.length());

        return 1.0 - ((double) distance / maxLen);
    }

    /**
     * 计算Levenshtein编辑距离
     * 使用标准DP算法，时间复杂度O(n*m)，空间复杂度O(min(n,m))
     */
    private static int levenshteinDistance(String s1, String s2) {
        // 空间优化：使用两行DP
        int len1 = s1.length();
        int len2 = s2.length();

        // 确保 len1 <= len2 以减少空间使用
        if (len1 > len2) {
            String tmp = s1;
            s1 = s2;
            s2 = tmp;
            int tmpLen = len1;
            len1 = len2;
            len2 = tmpLen;
        }

        int[] prev = new int[len1 + 1];
        int[] curr = new int[len1 + 1];

        // 初始化第一行
        for (int i = 0; i <= len1; i++) {
            prev[i] = i;
        }

        for (int j = 1; j <= len2; j++) {
            curr[0] = j;
            for (int i = 1; i <= len1; i++) {
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                curr[i] = Math.min(
                        Math.min(curr[i - 1] + 1, prev[i] + 1),
                        prev[i - 1] + cost
                );
            }
            // 交换行
            int[] temp = prev;
            prev = curr;
            curr = temp;
        }

        return prev[len1];
    }
}
