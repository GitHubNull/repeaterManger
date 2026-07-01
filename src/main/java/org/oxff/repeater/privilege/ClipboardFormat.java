package org.oxff.repeater.privilege;

/**
 * Clipboard content format enum
 */
public enum ClipboardFormat {
    RAW_HTTP,       // Raw HTTP message (starts with METHOD / HTTP)
    FETCH_BROWSER,  // Chrome "Copy as fetch"
    FETCH_NODEJS,   // Chrome "Copy as fetch (Node.js)"
    UNKNOWN         // Unrecognized
}
