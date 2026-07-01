package org.oxff.repeater.io;

class ParsedHttpMessage {
    String method;
    String requestTarget;
    com.google.gson.JsonArray headers;
    String body;
    String contentType;
    int statusCode;
    String statusText;
}
