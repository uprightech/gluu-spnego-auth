package org.gluu.oxauth.spnego.impl.http;


public class HttpAuthorization {

    private final HttpAuthorizationScheme scheme;
    private final String credentials;

    public HttpAuthorization(final HttpAuthorizationScheme scheme,final String credentials) {
        
        this.scheme = scheme;
        this.credentials = credentials;
        
    }

    public final String getCredentials() {

        return this.credentials;
    }

    public final HttpAuthorizationScheme getScheme() {

        return this.scheme;
    }
}