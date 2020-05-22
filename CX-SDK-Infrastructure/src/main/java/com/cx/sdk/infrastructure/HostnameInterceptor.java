package com.cx.sdk.infrastructure;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.LogicalHandler;
import javax.xml.ws.handler.LogicalMessageContext;
import javax.xml.ws.handler.MessageContext;
import java.net.URL;

public class HostnameInterceptor implements LogicalHandler<LogicalMessageContext> {

    private static final Logger logger = LoggerFactory.getLogger(HostnameInterceptor.class);
    private String hostName;

    public HostnameInterceptor(String hostName) {
        this.hostName = hostName;
    }

    @Override
    public boolean handleMessage(LogicalMessageContext context) {
        try {
            String urlStr = (String) context.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY);
            URL originalUrl = new URL(urlStr);
            String protocol = originalUrl.getProtocol();
            String host = originalUrl.getHost();
            int port = originalUrl.getPort();
            String path = originalUrl.getPath();

            String newHost = this.hostName;

            logger.info("[HostnameInterceptor] host: " + host + ", After replace: " + newHost);
            if (isNotEmpty(newHost) && !newHost.equalsIgnoreCase(host)) {
                URL newUrl = new URL(protocol, newHost, port, path);
                context.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, newUrl.toString());
            }
        } catch (Exception e) {
            logger.error("Fail to process Checkmarx hostname", e);
        }
        return true;
    }

    @Override
    public boolean handleFault(LogicalMessageContext context) {
        return true;
    }

    @Override
    public void close(MessageContext context) {

    }

    public static boolean isEmpty(CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

    public static boolean isNotEmpty(CharSequence cs) {
        return !isEmpty(cs);
    }

}
