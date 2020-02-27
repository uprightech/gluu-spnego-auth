package org.gluu.oxauth.spnego.impl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuthContext {

    final private HttpServletRequest request;
    final private HttpServletResponse response;
    
    public AuthContext(final HttpServletRequest request,final HttpServletResponse response) {

        this.request = request;
        this.response = response;
    }
}