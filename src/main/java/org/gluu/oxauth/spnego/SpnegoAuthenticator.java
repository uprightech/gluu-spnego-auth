package org.gluu.oxauth.spnego;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

public class SpnegoAuthenticator {

    private static final GSSManager GSS_MANAGER = GSSManager.getInstance();

    private LoginContext loginContext;
    private GSSCredential serverCredentials;
    private boolean allowDelegation;
    
    public void init(KerberosConfiguration config) {

        if(!config.hasKerberosConfigFile())
            throw new SpnegoError("Kerberos configuration file (krb5.conf) not specified");
        
        System.setProperty("java.security.krb5.conf",config.getKerberosConfigFile());

        try {
            this.allowDelegation = config.allowDelegation();
            this.loginContext = new LoginContext("does-not-matter",null,null,config.getJaasConfiguration());
            this.loginContext.login();
            this.serverCredentials = createGssCredential();

        }catch(LoginException e) {
            throw new SpnegoError("SpnegoAuthenticator init() failed",e);
        }catch(SecurityException e) {
            throw new SpnegoError("SpnegoAuthenticator init() failed",e);
        }catch(PrivilegedActionException e) {
            throw new SpnegoError("SpnegoAuthenticator init() failed",e);
        }
    }

    public void shutdown() {

        if(loginContext!=null) {
            try {
                loginContext.logout();
            }catch(LoginException e) {

            }
        }

        if(serverCredentials != null) {
            try {
                serverCredentials.dispose();
            }catch(GSSException e) {

            }
        }
    }

    private final GSSCredential createGssCredential() throws PrivilegedActionException {

        GssPrivilegedExceptionAction action = new GssPrivilegedExceptionAction(GSS_MANAGER,Utils.SPNEGO_OID);
        return Subject.doAs(loginContext.getSubject(),action);
    }


    private static class GssPrivilegedExceptionAction implements PrivilegedExceptionAction<GSSCredential> {

        private GSSManager gssManager;
        private Oid oid;

        public GssPrivilegedExceptionAction(GSSManager gssManager,Oid oid) {

            this.gssManager = gssManager;
            this.oid = oid;
        }

        @Override
        public GSSCredential run() throws GSSException {
            
            return gssManager.createCredential(
                null,
                GSSCredential.INDEFINITE_LIFETIME,
                oid,
                GSSCredential.ACCEPT_ONLY
            );
        } 
    }
}