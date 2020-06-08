# Spnego Authentication Script 
# Copyright (c) 2020 Gluu Inc. 
# Author Rolain Djeumen <rolain@gluu.org>
#

from java.util import HashMap , Arrays
from javax.faces.context import FacesContext
from org.gluu.jsf2.service import FacesService
from org.gluu.model.custom.script.type.auth import PersonAuthenticationType
from org.gluu.oxauth.model.config import Constants
from org.gluu.oxauth.security import Identity
from org.gluu.oxauth.spnego import SpnegoAuthError
from org.gluu.oxauth.spnego import SpnegoAuthenticatorFactory, SpnegoConfigProvider, SpnegoUtil, SpnegoConstants
from org.gluu.oxauth.service import AuthenticationService, SessionIdService , UserService
from org.gluu.service.cdi.util import CdiUtil
from org.gluu.util import StringHelper


class PersonAuthentication(PersonAuthenticationType):
    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis
    
    def init(self, configurationAttributes):
        print "SPNEGO. Init"
        self.spnegoTokenWorkingParameter = ""
        self.spnegoDebug = False
        self.alternativeAcr = None
        self.configProvider = self.createSpnegoConfiguration(configurationAttributes)
        if self.configProvider == None:
            print "SPNEGO. Init fail. Some configuration parameters may be missing"
            return False
        if (self.spnegoDebug is True):
            print "SPNEGO. Debug Enabled"
            SpnegoUtil.enableDebug(True)
        else:
            print "SPNEGO. Debug Disabled"
            SpnegoUtil.enableDebug(False)
        
        SpnegoUtil.setKerberosConfigFile(self.configProvider.getKerberosConfigFile())
        self.authenticatorFactory = SpnegoAuthenticatorFactory()
        print "SPNEGO. Init success"
        return True
        
    
    def destroy(self, configurationAttributes):
        print "SPNEGO. Destroy"
        self.configProvider = None
        self.authenticatorFactory = None
        print "SPNEGO. Destroy Success"
        return True
    
    def getApiVersion(self):
        print "SPNEGO. getApiVersion()"
        return 1
    
    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        print "SPNEGO. isValidAuthenticationMethod()"
        identity = CdiUtil.bean(Identity)
        spnego_fatal_error = identity.getWorkingParameter('spnego_fatal_error')
        if spnego_fatal_error is True and self.alternativeAcr is not None:
            print "SPNEGO. Invalid authentication method"
            return False

        if (self.parseSpnegoAlternateAcr() is not None) and (self.alternativeAcr is not None):
            print "SPNEGO. Invalid authentication method. Determined from request params"
            return False
        
        print "SPNEGO. This is a valid authentication method"
        return True
    
    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        print "SPNEGO. getAlternativeAuthenticationMethod()"
        identity = CdiUtil.bean(Identity)
        spnego_fatal_error = identity.getWorkingParameter('spnego_fatal_error')
        if spnego_fatal_error is True and self.alternativeAcr is not None:
            print "SPNEGO. Alternative acr %s" % (self.alternativeAcr)
            return self.alternativeAcr

        if (self.parseSpnegoAlternateAcr() is not None) and (self.alternativeAcr is not None):
            print "SPNEGO. Alternative acr from query string %s" % (self.alternativeAcr)
            return self.alternativeAcr
        
        print "SPNEGO. No alternative acr"
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        print "SPNEGO. authenticate()"
        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        authenticationService = CdiUtil.bean(AuthenticationService)
        if identity.getWorkingParameter('spnego_auth_success') is True:
            print "SPNEGO. Handshake complete"
            username = identity.getWorkingParameter('spnego_username')
            credentials.setUsername(username)
            return authenticationService.authenticate(username)
        else:
            print "SPNEGO. Authentication failed"
        return False
    
    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "SPNEGO. prepareForStep()"
        if (step==1):
            return self.prepareForFirstStep(configurationAttributes,requestParameters,step)
        return False
    
    def prepareForFirstStep(self, configurationAttributes, requestParameters, step):
        if (self.getAuthenticatedUser() is not None):
            print "SPNEGO. User is already authenticated"
            return False
        
        identity = CdiUtil.bean(Identity)
        if(identity.getWorkingParameter('spnego_auth_success') is True):
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg',None)
        
        if self.alternativeAcr is None:
            identity.setWorkingParameter('spnego_valid_alternative_acr',False)
            identity.setWorkingParameter('spnego_alternative_acr',None)
        else:
            identity.setWorkingParameter('spnego_valid_alternative_acr',True)
            identity.setWorkingParameter('spnego_alternative_acr',self.alternativeAcr)
        
        httpauth = self.parseHttpAuthorization()
        if (httpauth is None):
            print "SPNEGO. No authorization headers"
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg','spnego.error.no_auth_header')
            authn_header = SpnegoUtil.buildAuthenticateHeaderValue(None)
            self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authn_header)
            self.setResponseHttpStatus(SpnegoConstants.HTTP_UNAUTHORIZED_STATUS_CODE)
            return True
        
        if (not StringHelper.equalsIgnoreCase(httpauth.getScheme(),SpnegoConstants.NEGOTIATE_AUTH_SCHEME)):
            print "SPNEGO. Unsupported authentication scheme (%s)" % (httpauth.getScheme())
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg','spnego.error.unsupported_auth_scheme')
            if self.alternativeAcr is not None:
                identity.setWorkingParameter('spnego_fatal_error',True)
                authn_header = SpnegoUtil.buildAuthenticateHeaderValue(None)
                self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authn_header)
                self.setResponseHttpStatus(SpnegoConstants.HTTP_UNAUTHORIZED_STATUS_CODE)
            return True
        
        config_provider = self.configProvider
        auth_token = httpauth.getToken()
        spnego_authenticator = self.authenticatorFactory.createAuthenticator(auth_token,config_provider)
        try:
            spnego_principal = spnego_authenticator.authenticate()
        except SpnegoAuthError:
            identity.setWorkingParameter('spnego_fatal_error',True)
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg','spnego.error.fatal_error')
            authn_header = SpnegoUtil.buildAuthenticateHeaderValue(None)
            self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authn_header)
            self.setResponseHttpStatus(SpnegoConstants.HTTP_UNAUTHORIZED_STATUS_CODE)
            return True

        if (spnego_principal is None):
            print "SPNEGO. Authentication handshake incomplete"
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg','spnego.error.handshake_incomplete')
            authn_header = self.buildAuthenticationHeader(spnego_authenticator)
            self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authn_header)
            self.setResponseHttpStatus(SpnegoConstants.HTTP_UNAUTHORIZED_STATUS_CODE)
            return True
        
        user = self.findUser(spnego_principal.getUsername())
        if (user is None):
            print "SPNEGO. User '%s' not found in the database" % (spnego_principal.getUsername())
            identity.setWorkingParameter('spnego_auth_success',False)
            identity.setWorkingParameter('spnego_error_msg','spnego.error.user_not_found')
        else:
            print "SPNEO. Authentication successful for `%s`" % (spnego_principal.getUsername())
            identity.setWorkingParameter('spnego_auth_success',True)
            identity.setWorkingParameter('spnego_principal',spnego_principal.getPrincipalName())
            identity.setWorkingParameter('spnego_username',spnego_principal.getUsername())
        
        if (spnego_authenticator.getResponseToken() is not None):
            authn_header = self.buildAuthenticationHeader(spnego_authenticator)
            self.addHttpResponseHeader(SpnegoConstants.WWW_AUTHENTICATE_HEADER_NAME,authn_header)
        
        return True
        

        

    def getExtraParametersForStep(self, configurationAttributes, step):
        if (step == 1):
            return Arrays.asList("spnego_token","spnego_principal","spnego_auth_success","spnego_username","spnego_fatal_error")
        elif (step == 2):
            return Arrays.asList("spnego_token","spnego_principal","spnego_auth_success","spnego_username","spnego_fatal_error")
        return None
    
    def getCountAuthenticationSteps(self, configurationAttributes):
        print "getCountAuthenticationSteps()"
        return 1
    
    def getPageForStep(self, configurationAttributes, step):
        print "getPageForStep() ",step
        if (step == 1):
            return "/spnego/login.xhtml"
        return ""
    
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

    def parseSpnegoAlternateAcr(self):
        facesContext = CdiUtil.bean(FacesContext)
        request = facesContext.getExternalContext().getRequest()
        return request.getParameter('alternate_acr')
    
    def getAuthenticatedUser(self):
        authenticationService = CdiUtil.bean(AuthenticationService)
        return authenticationService.getAuthenticatedUser()

    def findUser(self, username):
        userService = CdiUtil.bean(UserService)
        user = userService.getUser(username,"uid")
        return user
    
    def buildAuthenticationHeader(self, authenticator):
        if authenticator.getResponseToken() is None:
            return SpnegoUtil.buildAuthenticateHeaderValue(None)
        else:
            return SpnegoUtil.buildAuthenticateHeaderValue(authenticator.getResponseToken())

    
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
            if StringHelper.equalsIgnoreCase("true",debugValue) is True:
                self.spnegoDebug = True
        else:
            config.setAdditionalJaasParameter("debug","false")
            
        
        if configurationAttributes.containsKey("krb5_login_use_ticket_cache"):
            useTicketCache = configurationAttributes.get("krb5_login_use_ticket_cache").getValue2()
            config.setAdditionalJaasParameter("useTicketCache",useTicketCache)
        
        if configurationAttributes.containsKey("krb5_login_ticket_cache"):
            ticketCache = configurationAttributes.get("krb5_login_ticket_cache").getValue2()
            config.setAdditionalJaasParameter("ticketCache",ticketCache)
        
        if configurationAttributes.containsKey("krb5_login_renew_tgt"):
            renewTgt = configurationAttributes.get("krb5_login_renew_tgt").getValue2()
            config.setAdditionalJaasParameter("renewTGT",renewTgt)
        
        if configurationAttributes.containsKey("kerberos_alternative_acr"):
            self.alternativeAcr = configurationAttributes.get("kerberos_alternative_acr").getValue2()
        
        return config
