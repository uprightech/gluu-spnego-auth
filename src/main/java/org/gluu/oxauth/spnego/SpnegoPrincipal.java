package org.gluu.oxauth.spnego;

import org.ietf.jgss.GSSCredential;

public class SpnegoPrincipal {

    private final String username;
    private final String domain;
    private final GSSCredential delegCredential;

    public SpnegoPrincipal(final String principalName,final GSSCredential delegCredential) {

        this.delegCredential = delegCredential;
        String [] parts = principalName.split("@");
        if(parts.length != 2) {
            this.username = null;
            this.domain = null;
            return;
        }
        this.username = parts[0];
        this.domain   = parts[1];
    }

    public final String getUsername() {

        return this.username;
    }

    public final String getDomain() {

        return this.domain;
    }

    public final String getPrincipalName() {

        return username + "@" + domain;
    }

    public final  GSSCredential getDelegCredential() {

        return this.delegCredential;
    }

}