package org.oxff.repeater.ui;

import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 搜索配置数据类 - 定义搜索范围、匹配模式和文本
 */
public record SearchConfig(
    Set<SearchScope> scope,
    String text,
    boolean isRegex,
    boolean caseSensitive
) {

    /**
     * 搜索范围枚举
     */
    public enum SearchScope {
        URL,    // 搜索 URL 列 (domain + path + query)
        HEADER, // 搜索请求头
        BODY    // 搜索请求体
    }

    /**
     * 判断给定内容是否匹配当前搜索配置
     *
     * @param content 要匹配的文本内容
     * @return true 如果匹配成功，false 如果不匹配或搜索文本为空
     */
    public boolean matches(String content) {
        if (content == null) {
            return false;
        }
        if (text == null || text.isEmpty()) {
            return true; // 空搜索文本不过滤
        }

        if (isRegex) {
            try {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern pattern = Pattern.compile(text, flags);
                return pattern.matcher(content).find();
            } catch (PatternSyntaxException e) {
                return false; // 无效正则不匹配
            }
        } else {
            // 关键词匹配
            if (caseSensitive) {
                return content.contains(text);
            } else {
                return content.toLowerCase().contains(text.toLowerCase());
            }
        }
    }
}