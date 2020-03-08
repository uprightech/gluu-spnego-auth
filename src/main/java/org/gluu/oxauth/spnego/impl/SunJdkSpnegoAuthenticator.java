package org.gluu.oxauth.spnego.impl;

import java.util.Base64;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;

import org.gluu.oxauth.spnego.SpnegoAuthenticator;
import org.gluu.oxauth.spnego.SpnegoConfigProvider;
import org.gluu.oxauth.spnego.SpnegoConstants;
import org.gluu.oxauth.spnego.SpnegoPrincipal;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

public class SunJdkSpnegoAuthenticator implements SpnegoAuthenticator {

    private KerberosServerSubjectAuthenticator serverSubjectAuthenticator;
    private String spnegoCredentials = null;
    private String responseToken = null;

    public SunJdkSpnegoAuthenticator(String spnegoCredentials,SpnegoConfigProvider configProvider) {

        this.serverSubjectAuthenticator = new KerberosServerSubjectAuthenticator(configProvider);
        this.spnegoCredentials = spnegoCredentials;
    }


    public final String getResponseToken() {

        return this.responseToken;
    }

    @Override
    public SpnegoPrincipal authenticate() {

        SpnegoPrincipal principal = null;
        try {
            Subject serverSubject = serverSubjectAuthenticator.authenticateServerSubject();
            principal = Subject.doAs(serverSubject,new AcceptSecContext());
        }catch(Exception e) {

        }finally {
            serverSubjectAuthenticator.logoutServerSubject();
        }
        return principal;
    }


    private class AcceptSecContext implements PrivilegedExceptionAction<SpnegoPrincipal> {

        @Override
        public SpnegoPrincipal run() throws Exception {
            GSSContext context = null;
            try {
                context = establishSpnegoContext();
                if(context.isEstablished()) {
                    if(context.getSrcName() == null) {
                        return null;
                    }
                    GSSCredential delegCredential = null;
                    String principalName = context.getSrcName().toString();
                    if(context.getCredDelegState()) {
                        delegCredential = context.getDelegCred();
                    }
                    return new SpnegoPrincipal(principalName,delegCredential);
                }else {
                    return null;
                }
            }finally {
                if(context != null)
                    context.dispose();
            }
        }
    }

    protected GSSContext establishSpnegoContext() throws GSSException, IOException {

        GSSManager gssManager = GSSManager.getInstance();
        GSSCredential gssCredential = gssManager.createCredential(null,GSSCredential.INDEFINITE_LIFETIME,
            getSupportedMechanisms(),GSSCredential.ACCEPT_ONLY);
        GSSContext context = gssManager.createContext(gssCredential);
        byte [] inputToken = Base64.getDecoder().decode(this.spnegoCredentials);
        byte [] respToken = context.acceptSecContext(inputToken,0,inputToken.length);
        responseToken = Base64.getEncoder().encodeToString(respToken);

        return context;
    }

    protected Oid [] getSupportedMechanisms() {

        return new Oid [] {
            SpnegoConstants.SPNEGO_OID,
            SpnegoConstants.KRB5_OID
        };
    }
}