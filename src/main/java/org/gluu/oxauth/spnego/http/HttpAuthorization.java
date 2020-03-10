package org.gluu.oxauth.spnego.http;

public class HttpAuthorization {

    public static final String BASIC_SCHEME = "Basic";
    public static final String BEARER_SCHEME = "Bearer";
    public static final String NEGOTIATE_SCHEME = "Negotiate";

    private final String scheme;
    private final String token;

    public HttpAuthorization(final String scheme, final String token) {

        this.scheme = scheme;
        this.token  = token;
    }

    public final String getScheme() {

        return this.scheme;
    }

    public final String getToken() {

        return this.token;
    }

    public final boolean isBasicScheme()  {

        return BASIC_SCHEME.equalsIgnoreCase(scheme);
    }

    public final boolean isBearerScheme() {

        return BEARER_SCHEME.equalsIgnoreCase(scheme);
    }

    public final boolean isNegotiateScheme() {

        return NEGOTIATE_SCHEME.equalsIgnoreCase(scheme);
    }

    public final boolean isKnownScheme() {

        return isBasicScheme() || isBearerScheme() || isNegotiateScheme();
    }
}