package org.gluu.oxauth.spnego;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

public class SpnegoConfigProvider {

    private static final String KERBEROS_AUTH_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String IS_INITIATOR_JAAS_OPT = "isInitiator";
    private static final String USE_KEYTAB_JAAS_OPT = "useKeyTab";
    private static final String DO_NOT_PROMPT_JAAS_OPT = "doNotPrompt";
    private static final String STORE_KEY_JAAS_OPT = "storeKey";
    private static final String PRINCIPAL_JAAS_OPT = "principal";
    private static final String KEYTAB_JAAS_OPT = "keyTab";

    private String kerberosConfigFile;
    private String keyTabFile;
    private String serverPrincipal;
    private Map<String,Object> additionalJaasParameters;
    private boolean credentialDelegation;

    public SpnegoConfigProvider() {

        this.additionalJaasParameters = new HashMap<String,Object>();
        this.credentialDelegation = false;
    }

    public void setKerberosConfigFile(String kerberosConfigFile) {

        this.kerberosConfigFile = kerberosConfigFile;
    } 

    public void setKeyTabFile(String keyTabFile) {
        this.keyTabFile = keyTabFile;
    }

    public void setServerPrincipal(String serverPrincipal) {

        this.serverPrincipal = serverPrincipal;
    }

    public void setAdditionalJaasParameter(String name,String value) {

        this.additionalJaasParameters.put(name,value);
    }

    public String getKerberosConfigFile() {

        return this.kerberosConfigFile;
    }

    public boolean getCredentialDelegation() {

        return this.credentialDelegation;
    }

    public Configuration getJaasConfiguration() {

        return new Configuration() {

            @Override
            public AppConfigurationEntry [] getAppConfigurationEntry(String name) {
                Map<String,Object> options = new HashMap<String,Object>();
                options.put(IS_INITIATOR_JAAS_OPT,"false");
                options.put(USE_KEYTAB_JAAS_OPT,"true");
                options.put(DO_NOT_PROMPT_JAAS_OPT,"true");
                options.put(STORE_KEY_JAAS_OPT,"true");

                if(serverPrincipal != null) {
                    options.put(PRINCIPAL_JAAS_OPT,serverPrincipal);
                }

                if(keyTabFile != null) {
                    options.put(KEYTAB_JAAS_OPT,keyTabFile);
                }

                if(!additionalJaasParameters.isEmpty()) {
                    Set<String> keyset = additionalJaasParameters.keySet();
                    Iterator<String> ksiter = keyset.iterator();
                    while(ksiter.hasNext()) {
                        String key = ksiter.next();
                        Object val = additionalJaasParameters.get(key);
                        options.putIfAbsent(key,val);
                    }
                }

                AppConfigurationEntry krbLoginConf = new AppConfigurationEntry(KERBEROS_AUTH_MODULE,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,options);
                
                return new AppConfigurationEntry [] { krbLoginConf};
            }
        };
    }
}