package com.cx.sdk.oidcLogin;


import com.cx.sdk.oidcLogin.exceptions.CxRestLoginException;
import com.cx.sdk.oidcLogin.restClient.ICxServer;
import com.cx.sdk.oidcLogin.webBrowsing.AuthenticationData;
import com.cx.sdk.oidcLogin.webBrowsing.IOIDCWebBrowser;
import com.cx.sdk.oidcLogin.webBrowsing.LoginData;

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
        if (cxServer.getCxVersion(clientName).equals("Pre 9.0")) {
            throw new CxRestLoginException("The Cx version is either older than 9.0 or the server can't be reached");
        }

        AuthenticationData authenticationData = webBrowser.browseAuthenticationData(cxServer.getServerURL(), clientName);

        if (authenticationData.wasCanceled) {
            return new LoginData(true);
        }

        LoginData loginData = cxServer.login(authenticationData.code);
        return loginData;
    }
}