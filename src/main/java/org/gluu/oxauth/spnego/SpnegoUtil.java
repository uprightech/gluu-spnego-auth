package org.gluu.oxauth.spnego;

import org.gluu.oxauth.spnego.http.HttpAuthorization;


public class SpnegoUtil  {

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


    public static final void setKerberosConfigFile(final String configFile) {

        System.setProperty(SpnegoConstants.KRB5_CONFIG_FILE,configFile);
    }

    public static final void enableDebug(boolean enabled) {

        String debugval = (enabled==true?"true":"false");
        System.setProperty(SpnegoConstants.KRB5_DEBUG_FLAG,debugval);
        System.setProperty(SpnegoConstants.SPNEGO_DEBUG_FLAG,debugval);
        System.setProperty(SpnegoConstants.JGSS_DEBUG_FLAG,debugval);
    }
}