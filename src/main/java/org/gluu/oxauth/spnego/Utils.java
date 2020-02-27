package org.gluu.oxauth.spnego;

import java.util.Base64;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.gluu.oxauth.spnego.impl.http.HttpAuthorization;
import org.gluu.oxauth.spnego.impl.http.HttpAuthorizationScheme;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;


public class Utils {

    public static final Oid SPNEGO_OID;

    private static final String WWW_AUTHENTICATE_HEADER_NAME = "WWW-Authenticate";
    private static final String HTTP_AUTHORIZATION_HEADER_NAME = "Authorization";
    private static final String SPNEGO_OID_STR = "1.3.6.1.5.5.2";

    static {

        Oid oid = null;
        try {
            oid = new Oid(SPNEGO_OID_STR);
        }catch(GSSException e) {

        }
        SPNEGO_OID = oid;
    }
    
    public static final HttpAuthorization parseHttpAuthorization(HttpServletRequest request) {
        
        String auth_header_value = request.getHeader(HTTP_AUTHORIZATION_HEADER_NAME);
        if(auth_header_value==null || auth_header_value.isEmpty()) {

            return null;
        }
        
        String [] hvparts = auth_header_value.trim().split("\\s+");
        if(hvparts.length != 2) {
            return null;
        }

        HttpAuthorizationScheme scheme = HttpAuthorizationScheme.fromSchemeName(hvparts[0].trim());
        return new HttpAuthorization(scheme,hvparts[1].trim());
    }


    public static final void addSpnegoHeader(byte [] credentials,HttpServletResponse response) {

        String value = null;
        if(credentials == null) {
            value = HttpAuthorizationScheme.NEGOTIATE.getSchemeName();
        }else {
            value = String.format("%s %s",HttpAuthorizationScheme.NEGOTIATE.getSchemeName(),
            Base64.getEncoder().encodeToString(credentials));
        }
        response.addHeader(WWW_AUTHENTICATE_HEADER_NAME,value);
    }
}