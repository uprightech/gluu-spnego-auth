package org.gluu.oxauth.spnego;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public class SpnegoConstants {

    public static final String  NEGOTIATE_AUTH_SCHEME = "Negotiate";
    public static final String  KRB5_CONFIG_FILE = "java.security.krb5.conf";
    public static final String  WWW_AUTHENTICATE_HEADER_NAME = "WWW-Authenticate";
    public static final String  AUTHORIZATION_HEADER_NAME = "Authorization";
    public static final String  KRB5_DEBUG_FLAG = "sun.security.krb5.debug";
    public static final String  JGSS_DEBUG_FLAG = "sun.security.jgss.debug";
    public static final String  SPNEGO_DEBUG_FLAG = "sun.security.spnego.debug";
    public static final Integer HTTP_UNAUTHORIZED_STATUS_CODE = 401;

    private static final String SPNEGO_OID_STR = "1.3.6.1.5.5.2";
    private static final String KRB5_OID_STR = "1.2.840.113554.1.2.2";
    private static final String KRB5_NAME_OID_STR = "1.2.840.113554.1.2.2.1";

    public static final Oid SPNEGO_OID;
    public static final Oid KRB5_OID;
    public static final Oid KRB5_NAME_OID;

    static {
        try {
            SPNEGO_OID = new Oid(SPNEGO_OID_STR);
            KRB5_OID = new Oid(SpnegoConstants.KRB5_OID_STR);
            KRB5_NAME_OID = new Oid(SpnegoConstants.KRB5_NAME_OID_STR);
        }catch(GSSException e) {
            throw new RuntimeException(e);
        }
    }
}