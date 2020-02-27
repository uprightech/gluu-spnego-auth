package org.gluu.oxauth.spnego;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

public class KerberosConfiguration {
    
    private static final String KERBEROS_AUTH_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    private String kerberosConfigFile;
    private String keyTabFile;
    private String serverPrincipal;
    private Map<String,Object> additionalJaasParameters;
    private boolean allowDelegation;

    public KerberosConfiguration() {

        this.additionalJaasParameters = new HashMap<String,Object>();
        this.allowDelegation = false;
    }

    public void setKerberosConfigFile(String kerberosConfigFile) {

        this.kerberosConfigFile = kerberosConfigFile;
    }

    public boolean hasKerberosConfigFile() {

        return this.kerberosConfigFile != null && !this.kerberosConfigFile.isEmpty();
    }

    public String getKerberosConfigFile() {

        return this.kerberosConfigFile;
    }

    public void setKeyTabFile(String keyTabFile) {

        this.keyTabFile = keyTabFile;
    }

    public void setServerPrincipal(String serverPrincipal) {

        this.serverPrincipal = serverPrincipal;
    }

    public void setAdditionalJaasParameter(String name,Object value) {

        this.additionalJaasParameters.put(name,value);
    }


    public Configuration getJaasConfiguration() {

        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String,Object> options = new HashMap<String,Object>();
                options.put("isInitiator","false");
                options.put("useKeyTab"  ,"true");
                options.put("doNotPrompt","true");
                options.put("storeKey","true");

                if(serverPrincipal != null) {
                    options.put("principal",serverPrincipal);
                }

                if(keyTabFile != null) {
                    options.put("keyTab",keyTabFile);
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

                AppConfigurationEntry krbLoginConfig = new AppConfigurationEntry(KERBEROS_AUTH_MODULE,
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,options);
                return new AppConfigurationEntry[] {krbLoginConfig};
            }
        };
    }

    public boolean allowDelegation() {

        return this.allowDelegation;
    }
}