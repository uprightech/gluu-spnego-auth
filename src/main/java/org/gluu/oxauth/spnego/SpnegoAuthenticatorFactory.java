package org.gluu.oxauth.spnego;

import org.gluu.oxauth.spnego.impl.SunJdkSpnegoAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SpnegoAuthenticatorFactory {

    private static final Logger logger = LoggerFactory.getLogger(SpnegoAuthenticatorFactory.class);

    public final SpnegoAuthenticator createAuthenticator(final String spnegoToken,final SpnegoConfigProvider configProvider) {

        if(logger.isDebugEnabled()) {
            logger.debug("Creating authenticator with spnego Token: " + spnegoToken);
        }
        return new SunJdkSpnegoAuthenticator(spnegoToken, configProvider);
    }
}