package org.gluu.oxauth.spnego;

import org.gluu.oxauth.spnego.impl.SunJdkSpnegoAuthenticator;

public class SpnegoAuthenticatorFactory {

    public final SpnegoAuthenticator createAuthenticator(final String spnegoToken,final SpnegoConfigProvider configProvider) {

        return new SunJdkSpnegoAuthenticator(spnegoToken, configProvider);
    }
}