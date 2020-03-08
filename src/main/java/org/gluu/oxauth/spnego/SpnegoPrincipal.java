package org.gluu.oxauth.spnego;

import org.ietf.jgss.GSSCredential;

public class SpnegoPrincipal {

    private final String principalName;
    private final GSSCredential delegationCredential;

    public SpnegoPrincipal(final String principalName,final GSSCredential delegationCredential) {

        this.principalName = principalName;
        this.delegationCredential = delegationCredential;
    }

    public final String getPrincipalName() {

        return this.principalName;
    }

    public final String getUsername() {

        return principalName.split("@")[0];
    }

    public final String getDomain() {

        return principalName.split("@")[1];
    }

    public final GSSCredential getDelegationCredential() {

        return this.delegationCredential;
    }
}