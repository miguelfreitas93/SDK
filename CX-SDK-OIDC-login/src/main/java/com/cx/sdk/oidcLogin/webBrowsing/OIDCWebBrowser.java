package com.cx.sdk.oidcLogin.webBrowsing;

import com.cx.sdk.domain.entities.ProxyParams;
import com.cx.sdk.oidcLogin.constants.Consts;
import com.cx.sdk.oidcLogin.exceptions.CxRestLoginException;
import com.google.common.base.Splitter;
import com.teamdev.jxbrowser.browser.Browser;
import com.teamdev.jxbrowser.browser.event.BrowserClosed;
import com.teamdev.jxbrowser.dom.Document;
import com.teamdev.jxbrowser.dom.Element;
import com.teamdev.jxbrowser.engine.Engine;
import com.teamdev.jxbrowser.engine.EngineOptions;
import com.teamdev.jxbrowser.engine.RenderingMode;
import com.teamdev.jxbrowser.event.Observer;
import com.teamdev.jxbrowser.frame.Frame;
import com.teamdev.jxbrowser.navigation.LoadUrlParams;
import com.teamdev.jxbrowser.navigation.event.FrameLoadFinished;
import com.teamdev.jxbrowser.net.HttpHeader;
import com.teamdev.jxbrowser.net.callback.*;
import com.teamdev.jxbrowser.os.Environment;
import com.teamdev.jxbrowser.view.swing.BrowserView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static com.teamdev.jxbrowser.os.Environment.isMac;
import static javax.swing.JOptionPane.OK_OPTION;

public class OIDCWebBrowser extends JFrame implements IOIDCWebBrowser {

    public static final String END_SESSION_FORMAT = "?id_token_hint=%s&post_logout_redirect_uri=%s";
    private String clientName;
    private JPanel contentPane;
    private String error;
    private Browser browser;
    private AuthenticationData response;
    private final Object lock = new Object();
    private Map<String, String> urlParamsMap;
    private String serverUrl;
    private String endSessionEndPoint;
    public static Engine ENGINE;
    private final Logger logger = LoggerFactory.getLogger(OIDCWebBrowser.class);

    private ProxyParams proxyParams;

    public OIDCWebBrowser(ProxyParams proxyParams) {
        this.proxyParams = proxyParams;
    }
    @Override
    public AuthenticationData browseAuthenticationData(String serverUrl, String clientName) throws Exception {
        logger.info("AuthenticationData initializing.. ");
        this.clientName = clientName;
        logger.info("Print clientName: " + this.clientName);
        this.serverUrl = serverUrl;
        logger.info("Print serverUrl: " + this.serverUrl);
        String authorizationEndpointUrl = serverUrl + Consts.AUTHORIZATION_ENDPOINT;
        logger.info("Print authorizationEndpointUrl: " + authorizationEndpointUrl);
        endSessionEndPoint = serverUrl + Consts.END_SESSION_ENDPOINT;
        logger.info("Print endSessionEndPoint: " + endSessionEndPoint);
        logger.info("Start initBrowser.");
        initBrowser(authorizationEndpointUrl);
        logger.info("Finish initBrowser");
        logger.info("Start waiting to Authentication.");
        waitForAuthentication();
        logger.info("Finish waiting for Authentication.");
        if (hasErrors()) {
            throw new CxRestLoginException(error);
        }

        return response;
    }

    private void initBrowser(String restUrl) {
        if (isMac()) {
            System.setProperty("java.ipc.external", "true");
            System.setProperty("jxbrowser.ipc.external", "true");

            /*if (!BrowserCore.isInitialized()) {
                BrowserCore.initialize();
            }*/
        }

        contentPane = new JPanel(new GridLayout(1, 1));
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        Engine engine = defaultEngine();

        engine.network().set(BeforeSendHeadersCallback.class, params -> {
            List<HttpHeader> headersList = new ArrayList<>(params.httpHeaders());
            headersList.add(HttpHeader.of("cxOrigin", clientName));
            return BeforeSendHeadersCallback.Response.override(headersList);
        });

        engine.network().set(AuthenticateCallback.class, createAuthenticationPopup(this));


        browser = engine.newBrowser();
        browser.navigation().on(FrameLoadFinished.class, AddResponsesHandler());

        String postData = getPostData();
        String pathToImage = "/checkmarxIcon.jpg";
        setIconImage(new ImageIcon(getClass().getResource(pathToImage), "checkmarx icon").getImage());

        SwingUtilities.invokeLater(() -> {
            browser.on(BrowserClosed.class, event ->
                    SwingUtilities.invokeLater(() -> {
                        this.setVisible(false);
                        this.dispose();
                    }));
            BrowserView browserView = BrowserView.newInstance(browser);
            contentPane.add(browserView);
            addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    close();
                    if (response == null) {
                        response = new AuthenticationData(true);
                    }
                    notifyAuthenticationFinish();
                }
            });
            setSize(700, 650);
            setLocationRelativeTo(null);
            getContentPane().add(contentPane, BorderLayout.CENTER);
            setVisible(true);
        });
        browser.navigation().loadUrlAndWait(restUrl + "?" + postData);
    }

    private static void close() {
        if (isMac()) {
            // On macOS the engine must be closed in UI thread
            ENGINE.close();
        } else {
            // On Windows and Linux it must be closed in non-UI thread
            new Thread(ENGINE::close).start();
        }
    }

    public static Engine defaultEngine() {
        if (ENGINE == null || ENGINE.isClosed()) {
            ENGINE = Engine.newInstance(EngineOptions
                    .newBuilder(RenderingMode.HARDWARE_ACCELERATED)
                    .userAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36")
                    .addSwitch("--disable-google-traffic")
                    .build());
            ENGINE.network().set(CanGetCookiesCallback.class, params -> CanGetCookiesCallback.Response.can());
            ENGINE.network().set(CanSetCookieCallback.class, params ->
                    CanSetCookieCallback.Response.can());
            ENGINE.network().set(VerifyCertificateCallback.class, params -> VerifyCertificateCallback.Response.valid());
        }

        return ENGINE;
    }

    private AuthenticateCallback createAuthenticationPopup(java.awt.Frame frame) {
        return (params, tell) -> SwingUtilities.invokeLater(() -> {
            if (params.isProxy() && proxyParams != null) {
                tell.authenticate(proxyParams.getUsername(),proxyParams.getPassword());
            }
            else {
                JPanel userPanel = new JPanel();
                userPanel.setLayout(new GridLayout(2, 2));
                JLabel usernameLabel = new JLabel("Username:");
                JLabel passwordLabel = new JLabel("Password:");
                JTextField username = new JTextField();
                JPasswordField password = new JPasswordField();
                userPanel.add(usernameLabel);
                userPanel.add(username);
                userPanel.add(passwordLabel);
                userPanel.add(password);
                int input = JOptionPane.showConfirmDialog(frame, userPanel,
                        String.format("Server :%s require username and password,Enter your credentials:",params.url()),
                        JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (input == OK_OPTION) {
                    // Authenticate with the particular username and password
                    tell.authenticate(username.getText(), new String(password.getPassword()));
                } else {
                    // Otherwise cancel the authentication.
                    tell.cancel();
                }
            }

        });
    }

    @Override
    public void logout(String idToken) {
        Engine engine = defaultEngine();
        browser = engine.newBrowser();
        browser.navigation().loadUrl(endSessionEndPoint + String.format(END_SESSION_FORMAT, idToken, serverUrl + "/cxwebclient/"));
        browser.navigation().on(FrameLoadFinished.class, disposeOnLoadDone());
    }

    private Observer<FrameLoadFinished> disposeOnLoadDone() {
        return param -> {
            param.frame().browser().close();
        };
    }

    private void configureBrowserEvents() {
        browser.navigation().on(FrameLoadFinished.class, obs -> {
        });
    }

    private void waitForAuthentication() {
        logger.info("waitForAuthentication");
        synchronized (lock) {
            try {
                logger.info("Waiting...");
                lock.wait();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private String getPostData() {
        StringBuilder sb = new StringBuilder();
        sb.append(Consts.CLIENT_ID_KEY);
        sb.append("=");
        sb.append(Consts.CLIENT_VALUE);
        sb.append("&");
        sb.append(Consts.SCOPE_KEY);
        sb.append("=");
        sb.append(Consts.SCOPE_VALUE);
        sb.append("&");
        sb.append(Consts.RESPONSE_TYPE_KEY);
        sb.append("=");
        sb.append(Consts.RESPONSE_TYPE_VALUE);
        sb.append("&");
        sb.append(serverUrl.endsWith("/") ? Consts.REDIRECT_URI_KEY + "=" + serverUrl : Consts.REDIRECT_URI_KEY + "=" + serverUrl + "/");
        return sb.toString();
    }

    private void notifyAuthenticationFinish() {
        synchronized (lock) {
            logger.info("will notify");
            lock.notify();
        }
    }

    private Observer<FrameLoadFinished> AddResponsesHandler() {
        return param -> {
            handleErrorResponse(param);
            handleResponse(param);
            if ((response != null && response.code != null) || hasErrors())
                closePopup();
        };
    }

    private void handleErrorResponse(FrameLoadFinished event) {
        if (event.frame().isMain()) {

            checkForUrlQueryErrors(event);
            if (!hasErrors())
                checkForBodyErrors(event);
        }
    }

    private void checkForUrlQueryErrors(FrameLoadFinished event) {
        if (!isUrlErrorResponse(event)) return;

        try {
            String queryStringParams = new URL(event.url()).getQuery();
            String[] params = queryStringParams.split("&");
            for (Integer i = 0; i < params.length; i++) {
                if (params[i].startsWith("Error")) {
                    error = java.net.URLDecoder.decode(params[i].substring(6), "UTF-8");
                    break;
                }
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    private boolean isUrlErrorResponse(FrameLoadFinished event) {
        return event.url().contains("Error=");
    }

    private void checkForBodyErrors(FrameLoadFinished event) {
        Frame frame = event.frame();
        Optional<Document> document = frame.document();
        String content = "";
        if (document.isPresent()) {
            Document d = document.get();
            Optional<Element> element = d.documentElement();
            content = element.isPresent() ? element.get().innerHtml() : "";
        }

        if (!isBodyErrorResponse(content)) return;
        handleInternalServerError(content);

        if (hasErrors() || !content.contains("messageDetails")) return;
        extractMessageErrorFromBody(content);
    }

    private void handleInternalServerError(String content) {
        if (content.contains("HTTP 500")) {
            error = "Internal server error";
        }
    }

    private void extractMessageErrorFromBody(String content) {
        String[] contentComponents = content.split("\\r?\\n");
        for (String component : contentComponents) {
            if (component.contains("messageDetails")) {
                error = component.split(":")[1].trim();
                TrimError();
                break;
            }
        }
    }

    private void TrimError() {
        if (error.startsWith("\""))
            error = error.substring(1);
        if (error.endsWith("\""))
            error = error.substring(0, error.length() - 1);
    }

    private boolean isBodyErrorResponse(String content) {
        return content.toLowerCase().contains("messagecode");
    }

    private boolean validateUrlResponse(FrameLoadFinished event) {
        return event.url().toLowerCase().contains(Consts.CODE_KEY);
    }

    private boolean hasErrors() {
        return error != null && !error.isEmpty();
    }

    private void handleResponse(FrameLoadFinished event) {
        if (event.frame().isMain() && (validateUrlResponse(event)) && !hasErrors()) {
            String validatedURL = event.url();
            extractReturnedUrlParams(validatedURL);
            response = new AuthenticationData(urlParamsMap.get(Consts.CODE_KEY));
        }
    }

    private Map<String, String> extractReturnedUrlParams(String validatedURL) {
        String query = validatedURL.split("\\?")[1];
        urlParamsMap = Splitter.on('&').trimResults().withKeyValueSeparator("=").split(query);
        return urlParamsMap;
    }

    private void closePopup() {
        dispatchEvent(new WindowEvent(OIDCWebBrowser.this, WindowEvent.WINDOW_CLOSING));
    }

    @Override
    public void disposeBrowser() {
        browser.close();
    }

}