package org.gluu.oxauth.spnego.impl.http;

public enum HttpAuthorizationScheme {
    BASIC("Basic"),
    BEARER("Bearer"),
    NEGOTIATE("Negotiate");

    private final String schemeName;

    private HttpAuthorizationScheme(final String schemeName) {
        this.schemeName = schemeName;
    }

    public final String getSchemeName() {

        return this.schemeName;
    }

    public static final HttpAuthorizationScheme fromSchemeName(String schemename) {

        HttpAuthorizationScheme ret = null;
        for(HttpAuthorizationScheme scheme: values()) {
            if(scheme.schemeName.equalsIgnoreCase(schemename)) {
                ret = scheme;
                break;
            }
        }
        return ret;
    }
}