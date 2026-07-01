package org.oxff.repeater.privilege;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Internal data structure: parsed fetch request
 */
class FetchRequest {
    String url;
    String method = "GET";
    final Map<String, String> headers = new LinkedHashMap<>();
    String body = null;
}
