# Spnego Authentication Script 
# Copyright (c) 2020 Gluu Inc. 
# Author Rolain Djeumen <rolain@gluu.org>
#

from javax.faces.context import FacesContext
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.spnego import SpnegoAuthenticatorFactory, SpnegoConfigProvider, SpnegoUtil, SpnegoConstants
from org.gluu.oxauth.service import AuthenticationService, SessionIdService
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
    
    def init(self, configurationAttributes):
        print "SPNEGO. Init"
        self.spnegoTokenWorkingParameter = ""
        self.configProvider = self.createSpnegoConfiguration(configurationAttributes)
        self.configProvider.setAdditionalJaasParameter("debug","true")
        if self.configProvider == None:
            print "SPNEGO. Init fail. Some configuration parameters may be missing"
            return False
        self.authenticatorFactory = SpnegoAuthenticatorFactory()
        SpnegoUtil.setKerberosConfigFile(self.configProvider.getKerberosConfigFile())
        SpnegoUtil.enableDebug(True)
        print "SPNEGO. Init success"
        return True
        
    
    def destroy(self, configurationAttributes):
        print "SPNEGO. Destroy"
        self.configProvider = None
        self.authenticatorFactory = None
        print "SPNEGO. Destroy Success"
        return True
    
    def getApiVersion(self):
        print "getApiVersion()"
        return 2
    
    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "isValidAuthenticationMethod()"
        return True
    
    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "getAlternativeAuthenticationMethod()"
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "authenticate()"
        return False
    
    def prepareForStep(self, configurationAttributes, requestParameters, step):
        # implement this first
        httpauth = self.parseHttpAuthorization()
        if (httpauth is None) and (self.getAuthenticatedUser() is None):
            # we're not authenticated and no authentication header was provided
            # 
            print "Not authenticated and no authentication header found"
            authHeaderValue = SpnegoUtil.buildAuthenticateHeaderValue(None)
            self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authHeaderValue)
            self.setResponseHttpStatus(SpnegoConstants.HTTP_UNAUTHORIZED_STATUS_CODE)
        elif (not httpauth is None) and (self.getAuthenticatedUser() is None):
            # we're not authenticated but we have an http authorization header
            if not StringHelper.equalsIgnoreCase(httpauth.getScheme(),SpnegoConstants.NEGOTIATE_AUTH_SCHEME):
                print "Unsupported authentication scheme"
            else:
                print "Attempting negotiate authentication: %s --> %s" % (httpauth.getScheme(),httpauth.getToken())
                token = httpauth.getToken()
                provider = self.configProvider
                authenticator = self.authenticatorFactory.createAuthenticator(token,provider)
                principal = authenticator.authenticate()

        return True
    
    def getExtraParametersForStep(self, configurationAttributes, step):
        print "getExtraParametersForStep() ",step
        return None
    
    def getCountAuthenticationSteps(self, configurationAttributes):
        print "getCountAuthenticationSteps()"
        return 0
    
    def getPageForStep(self, configurationAttributes, step):
        print "getPageForStep() ",step
        return "/spnego/login.xhtml"
    
    def getSpnegoResponseToken(self):
        identity = CdiUtil.bean(Identity)
        token = identity.getWorkingParameter("spnego_token")
        if StringHelper.isEmpty(token):
            return None
        else:
            return token
    
    def saveSpnegoResponseToken(self, token):
        identity = CdiUtil.bean(Identity)
        identity.setWorkingParameter("spnego_token",token)
    
    def setResponseHttpStatus(self, code):
        facesContext = CdiUtil.bean(FacesContext)
        facesContext.getExternalContext().setResponseStatus(code)
    
    def addHttpResponseHeader(self, name,value):
        facesContext = CdiUtil.bean(FacesContext)
        facesContext.getExternalContext().addResponseHeader(name,value)

    def parseHttpAuthorization(self):
        facesContext = CdiUtil.bean(FacesContext)
        request = facesContext.getExternalContext().getRequest()
        headerValue = request.getHeader(SpnegoConstants.AUTHORIZATION_HEADER_NAME)
        return SpnegoUtil.parseHttpAuthorization(headerValue)
    
    def getAuthenticatedUser(self):
        authenticationService = CdiUtil.bean(AuthenticationService)
        return authenticationService.getAuthenticatedUser()
    
    def createSpnegoConfiguration(self, configurationAttributes):

        if not configurationAttributes.containsKey("kerberos_config_file"):
            print "SPNEGO. Missing 'kerberos_config_file' configuration entry attribute"
            return None
        
        if not configurationAttributes.containsKey("kerberos_keytab_file"):
            print "SPNEGO. Missing 'kerberos_keytab_file' configuration entry attribute"
            return None
        
        if not configurationAttributes.containsKey("kerberos_server_principal"):
            print "SPNEGO. Missing 'kerberos_server_principal' configuration entry attribute"
            return None

        config = SpnegoConfigProvider()

        kerberosConfigFile = configurationAttributes.get("kerberos_config_file").getValue2()
        keyTabFile = configurationAttributes.get("kerberos_keytab_file").getValue2()
        serverPrincipal  = configurationAttributes.get("kerberos_server_principal").getValue2()
        config.setKerberosConfigFile(kerberosConfigFile)
        config.setKeyTabFile(keyTabFile)
        config.setServerPrincipal(serverPrincipal)

        if configurationAttributes.containsKey("krb5_login_debug"):
            debugValue = configurationAttributes.get("krb5_login_debug").getValue2()
            config.setAdditionalJaasParameter("debug",debugValue)
        
        if configurationAttributes.containsKey("krb5_login_use_ticket_cache"):
            useTicketCache = configurationAttributes.get("krb5_login_use_ticket_cache").getValue2()
            config.setAdditionalJaasParameter("useTicketCache",useTicketCache)
        
        if configurationAttributes.containsKey("krb5_login_ticket_cache"):
            ticketCache = configurationAttributes.get("krb5_login_ticket_cache").getValue2()
            config.setAdditionalJaasParameter("ticketCache",ticketCache)
        
        if configurationAttributes.containsKey("krb5_login_renew_tgt"):
            renewTgt = configurationAttributes.get("krb5_login_renew_tgt").getValue2()
            config.setAdditionalJaasParameter("renewTGT",renewTgt)
        

        return config
