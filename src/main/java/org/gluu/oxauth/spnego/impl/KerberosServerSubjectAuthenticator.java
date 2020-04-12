package org.gluu.oxauth.spnego.impl;

import java.io.IOException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.gluu.oxauth.spnego.SpnegoConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KerberosServerSubjectAuthenticator  {

    private static final Logger logger = LoggerFactory.getLogger(KerberosServerSubjectAuthenticator.class);

    private static final CallbackHandler DUMMY_CALLBACK_HANDLER = new CallbackHandler() {

        @Override
        public  void handle(Callback [] callbacks) throws IOException, UnsupportedCallbackException {

            throw new UnsupportedCallbackException(callbacks[0]);
        }
    };

    private final SpnegoConfigProvider configProvider;
    private LoginContext loginContext;


    public KerberosServerSubjectAuthenticator(final SpnegoConfigProvider configProvider) {

        this.configProvider = configProvider;
    }

    public Subject authenticateServerSubject() throws LoginException {

        logger.debug("Authenticating server subject");
        Configuration config = configProvider.getJaasConfiguration();
        loginContext = new LoginContext("does-not-matter",null,DUMMY_CALLBACK_HANDLER,config);
        loginContext.login();
        return loginContext.getSubject();
    }

    public void logoutServerSubject() {

        if(loginContext != null) {
            try {
                logger.debug("Logout server subject");
                loginContext.logout();
            }catch(LoginException e) {
                logger.error("Failed to logout kerberos server subject: " + configProvider.getServerPrincipal());
            }
        }
    }
}