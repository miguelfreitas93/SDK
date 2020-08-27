package com.cx.sdk.oidcLogin;


import com.cx.sdk.oidcLogin.exceptions.CxRestLoginException;
import com.cx.sdk.oidcLogin.exceptions.CxValidateResponseException;
import com.cx.sdk.oidcLogin.restClient.ICxServer;
import com.cx.sdk.oidcLogin.webBrowsing.AuthenticationData;
import com.cx.sdk.oidcLogin.webBrowsing.IOIDCWebBrowser;
import com.cx.sdk.oidcLogin.webBrowsing.LoginData;

import java.io.IOException;

public class CxOIDCConnector {
    private ICxServer cxServer;
    private String clientName;
    private IOIDCWebBrowser webBrowser;

    public CxOIDCConnector(ICxServer cxServer, IOIDCWebBrowser webBrowser, String clientName) {
        this.cxServer = cxServer;
        this.webBrowser = webBrowser;
        this.clientName = clientName;
    }

    public LoginData connect() throws Exception {
        String version ="";
        try {
            version= (String) cxServer.getCxVersion(clientName);
        } catch (IOException|CxValidateResponseException e) {
            throw new CxRestLoginException(e.getMessage());
        }

        if ("Pre 9.0".equals(version) ) {
            throw new CxRestLoginException("sast version is older than 9.x");
        }

        AuthenticationData authenticationData = webBrowser.browseAuthenticationData(cxServer.getServerURL(), clientName);

        if (authenticationData.wasCanceled) {
            return new LoginData(true);
        }

        LoginData loginData = cxServer.login(authenticationData.code);
        return loginData;
    }
}