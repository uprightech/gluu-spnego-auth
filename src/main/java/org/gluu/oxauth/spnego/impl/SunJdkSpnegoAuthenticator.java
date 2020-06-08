package org.gluu.oxauth.spnego.impl;

import java.util.Base64;
import java.io.IOException;
import java.security.PrivilegedExceptionAction;
import javax.security.auth.Subject;

import org.gluu.oxauth.spnego.SpnegoAuthError;
import org.gluu.oxauth.spnego.SpnegoAuthenticator;
import org.gluu.oxauth.spnego.SpnegoConfigProvider;
import org.gluu.oxauth.spnego.SpnegoConstants;
import org.gluu.oxauth.spnego.SpnegoPrincipal;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SunJdkSpnegoAuthenticator implements SpnegoAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(SunJdkSpnegoAuthenticator.class);

    private KerberosServerSubjectAuthenticator serverSubjectAuthenticator;
    private String spnegoCredentials = null;
    private String responseToken = null;

    public SunJdkSpnegoAuthenticator(String spnegoCredentials,SpnegoConfigProvider configProvider) {

        this.serverSubjectAuthenticator = new KerberosServerSubjectAuthenticator(configProvider);
        this.spnegoCredentials = spnegoCredentials;
    }

    @Override
    public final String getResponseToken() {

        return this.responseToken;
    }

    @Override
    public SpnegoPrincipal authenticate() {

        if(logger.isTraceEnabled()) {
            logger.trace("SPNEGO Authenticate with credentials: " + spnegoCredentials);
        }

        SpnegoPrincipal principal = null;
        try {
            Subject serverSubject = serverSubjectAuthenticator.authenticateServerSubject();
            principal = Subject.doAs(serverSubject,new AcceptSecContext());
        }catch(Exception e) {
            logger.debug("SPNEGO Authentication failed",e);
            throw new SpnegoAuthError("SPNEGO Authentication failed",e);
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
                logger.trace("Establishing SPNEGO security context");
                context = establishSpnegoContext();
                logAuthDetails(context);
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

    protected final void logAuthDetails(GSSContext gssContext) throws GSSException {
        if(logger.isDebugEnabled()) {
            String message = new StringBuilder("SPNEGO Security context accepted with token: " + responseToken)
                .append(", established: ").append(gssContext.isEstablished())
                .append(", credDelegState: ").append(gssContext.getCredDelegState())
                .append(", mutualAuthState: ").append(gssContext.getMutualAuthState())
                .append(", lifetime: ").append(gssContext.getLifetime())
                .append(", confState: ").append(gssContext.getConfState())
                .append(", integState: ").append(gssContext.getIntegState())
                .append(", srcName: ").append(gssContext.getSrcName())
                .append(", targName: ").append(gssContext.getTargName())
                .toString();
            
            logger.debug(message);
        }
    }
}