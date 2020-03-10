package org.gluu.oxauth.spnego.http;


public class HttpUtil  {

    public static final HttpAuthorization parseHttpAuthorization(final String authorizationValue) {
        
        if(authorizationValue == null || authorizationValue.isEmpty()) {
            return null;
        }

        String [] hvparts = authorizationValue.split("\\s+");
        if (hvparts.length != 2) {
            return null;
        }

        return new HttpAuthorization(hvparts[0].trim(),hvparts[1].trim());
    }

    public static final String buildAuthenticateHeaderValue(final String tokenResponse) {

        String value = null;
        if(tokenResponse == null) {
            value = HttpAuthorization.NEGOTIATE_SCHEME;
        }else {
            value = String.format("%s %s",HttpAuthorization.NEGOTIATE_SCHEME,tokenResponse);
        }
        return value;
    }

}