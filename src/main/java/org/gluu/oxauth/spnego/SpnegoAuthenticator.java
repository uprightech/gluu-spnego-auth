package org.gluu.oxauth.spnego;

public interface SpnegoAuthenticator {

    public SpnegoPrincipal authenticate();
    public String getResponseToken();
}