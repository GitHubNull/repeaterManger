package org.oxff.repeater.privilege;

import org.oxff.repeater.privilege.model.TokenLocation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP报文解析结果
 * 封装从HTTP报文中根据TokenLocation提取到的令牌值
 */
public class SessionParseResult {

    private final Map<Integer, String> extractedValues; // locationId -> value
    private final Map<Integer, TokenLocation> locationMap; // locationId -> TokenLocation
    private final String rawHeader;
    private final String rawBody;
    private final String contentType;

    public SessionParseResult(String rawHeader, String rawBody, String contentType,
                              Map<Integer, String> extractedValues,
                              Map<Integer, TokenLocation> locationMap) {
        this.rawHeader = rawHeader;
        this.rawBody = rawBody;
        this.contentType = contentType;
        this.extractedValues = extractedValues != null ? extractedValues : new LinkedHashMap<>();
        this.locationMap = locationMap != null ? locationMap : new LinkedHashMap<>();
    }

    /**
     * 获取指定位置ID提取到的值
     *
     * @return 值字符串，未匹配到返回null
     */
    public String getExtractedValue(int locationId) {
        return extractedValues.get(locationId);
    }

    /**
     * 获取所有提取到的值（非null）
     */
    public Map<Integer, String> getAllExtractedValues() {
        return new LinkedHashMap<>(extractedValues);
    }

    /**
     * 获取未匹配到值的TokenLocation列表
     */
    public List<TokenLocation> getUnmatchedLocations() {
        List<TokenLocation> unmatched = new ArrayList<>();
        for (Map.Entry<Integer, TokenLocation> entry : locationMap.entrySet()) {
            if (!extractedValues.containsKey(entry.getKey())) {
                unmatched.add(entry.getValue());
            }
        }
        return unmatched;
    }

    /**
     * 获取匹配率（0.0 ~ 1.0）
     */
    public double getMatchRate(List<TokenLocation> targetLocations) {
        if (targetLocations == null || targetLocations.isEmpty()) {
            return 0.0;
        }
        int matched = 0;
        for (TokenLocation loc : targetLocations) {
            if (extractedValues.containsKey(loc.getId())) {
                matched++;
            }
        }
        return (double) matched / targetLocations.size();
    }

    public String getRawHeader() {
        return rawHeader;
    }

    public String getRawBody() {
        return rawBody;
    }

    public String getContentType() {
        return contentType;
    }

    public Map<Integer, TokenLocation> getLocationMap() {
        return Collections.unmodifiableMap(locationMap);
    }

    /**
     * 根据header名称从rawHeader中提取值
     * 用于自动命名策略（JWT提取、Host推断等）
     *
     * @param headerName header名称（大小写不敏感）
     * @return header值，未找到返回null
     */
    public String getExtractedValueByHeaderName(String headerName) {
        if (rawHeader == null || headerName == null) {
            return null;
        }
        String headerNameLower = headerName.toLowerCase();
        String[] lines = rawHeader.split("\r\n");
        for (String line : lines) {
            int colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                String currentName = line.substring(0, colonIdx).trim().toLowerCase();
                if (currentName.equals(headerNameLower)) {
                    return line.substring(colonIdx + 1).trim();
                }
            }
        }
        return null;
    }
}
