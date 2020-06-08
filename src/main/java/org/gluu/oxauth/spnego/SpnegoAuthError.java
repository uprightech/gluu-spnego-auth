package org.gluu.oxauth.spnego;

public class SpnegoAuthError extends RuntimeException {

    /**
     *
     */
    private static final long serialVersionUID = -4080869405665539531L;


    public SpnegoAuthError(String msg) {
        super(msg);
    }

    public SpnegoAuthError(String msg, Throwable cause) {
        super(msg,cause);
    }
    
}