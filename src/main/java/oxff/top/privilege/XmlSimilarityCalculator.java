package oxff.top.privilege;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * XML 相似度计算器 - 无状态工具类
 * 基于 XML Tree Diff 算法，递归展平 XML 为 element-path/attr-name → value 映射后比较
 *
 * <p>优势：
 * <ul>
 *   <li>元素顺序无关 — 同级子元素顺序变化不影响相似度</li>
 *   <li>噪声过滤 — 动态属性值和时间戳自动归一化</li>
 *   <li>支持 SOAP — 对 SOAP Envelope/Body 结构透明</li>
 *   <li>精确差异定位 — 可扩展为返回差异路径列表</li>
 * </ul>
 */
public class XmlSimilarityCalculator {

    private XmlSimilarityCalculator() {
    }

    /**
     * 计算两个 XML 字符串的结构相似度
     *
     * @param xml1 第一个 XML 字符串
     * @param xml2 第二个 XML 字符串
     * @return 相似度值 0.0~1.0，1.0 表示完全相同
     */
    public static double similarity(String xml1, String xml2) {
        if (xml1 == null && xml2 == null) return 1.0;
        if (xml1 == null || xml2 == null) return 0.0;
        if (xml1.isEmpty() && xml2.isEmpty()) return 1.0;
        if (xml1.isEmpty() || xml2.isEmpty()) return 0.0;
        if (xml1.equals(xml2)) return 1.0;

        try {
            Document doc1 = parseXml(xml1);
            Document doc2 = parseXml(xml2);

            Map<String, String> map1 = flattenXml(doc1.getDocumentElement(), "");
            Map<String, String> map2 = flattenXml(doc2.getDocumentElement(), "");

            return computeMapSimilarity(map1, map2);
        } catch (Exception e) {
            // XML 解析失败，降级到 Jaccard
            return JaccardSimilarityCalculator.similarity(xml1, xml2);
        }
    }

    /**
     * 解析 XML 字符串为 Document
     */
    private static Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        // 禁用外部实体，防止 XXE
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * 递归展平 XML 元素为 path → value 映射
     *
     * @param element 当前 XML 元素
     * @param prefix  当前路径前缀
     * @return 展平后的映射（包含元素文本内容和属性值）
     */
    private static Map<String, String> flattenXml(Element element, String prefix) {
        Map<String, String> result = new HashMap<>();
        String tagName = element.getTagName();
        String currentPath = prefix.isEmpty() ? tagName : prefix + "/" + tagName;

        // 处理属性
        NamedNodeMap attributes = element.getAttributes();
        for (int i = 0; i < attributes.getLength(); i++) {
            Attr attr = (Attr) attributes.item(i);
            String attrPath = currentPath + "@" + attr.getName();
            result.put(attrPath, NoiseFilter.normalize(attr.getValue()));
        }

        // 收集直接文本内容（不包括子元素的文本）
        String textContent = getDirectTextContent(element);
        if (!textContent.isEmpty()) {
            result.put(currentPath + "#text", NoiseFilter.normalize(textContent));
        }

        // 处理子元素
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child instanceof Element childElement) {
                result.putAll(flattenXml(childElement, currentPath));
            }
        }

        return result;
    }

    /**
     * 获取元素的直接文本内容（忽略子元素的文本）
     */
    private static String getDirectTextContent(Element element) {
        StringBuilder sb = new StringBuilder();
        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE) {
                sb.append(child.getTextContent());
            }
        }
        return sb.toString().trim();
    }

    /**
     * 计算两个 path-value 映射的相似度（与 JSON 版本逻辑一致）
     */
    private static double computeMapSimilarity(Map<String, String> map1, Map<String, String> map2) {
        if (map1.isEmpty() && map2.isEmpty()) return 1.0;
        if (map1.isEmpty() || map2.isEmpty()) return 0.0;

        java.util.Set<String> allKeys = new java.util.HashSet<>(map1.keySet());
        allKeys.addAll(map2.keySet());

        int totalKeys = allKeys.size();
        int matchedKeys = 0;

        for (String key : allKeys) {
            String v1 = map1.get(key);
            String v2 = map2.get(key);

            if (v1 != null && v2 != null) {
                if (v1.equals(v2)) {
                    matchedKeys++;
                } else {
                    double valueSim = computeValueSimilarity(v1, v2);
                    matchedKeys += valueSim;
                }
            }
        }

        return (double) matchedKeys / totalKeys;
    }

    /**
     * 计算两个叶子值的相似度
     */
    private static double computeValueSimilarity(String v1, String v2) {
        if (v1.equals(v2)) return 1.0;
        if (v1.length() <= 50 && v2.length() <= 50) {
            return 0.0;
        }
        return JaccardSimilarityCalculator.similarity(v1, v2);
    }
}
