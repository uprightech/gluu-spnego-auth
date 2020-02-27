package org.gluu.oxauth.spnego;

public class SpnegoError extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SpnegoError(String msg) {
        super(msg);
    }

    public SpnegoError(String msg, Throwable cause) {
        super(msg,cause);
    }
}