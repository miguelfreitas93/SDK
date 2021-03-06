package com.cx.sdk.application.contracts.providers;

import com.cx.sdk.domain.Session;
import com.cx.sdk.domain.exceptions.SdkException;

/**
 * Created by ehuds on 2/25/2017.
 */
public interface LoginProvider {
    Session login() throws SdkException;

    void logout();

    boolean isTokenExpired(Long expirationTime);

    Session getAccessTokenFromRefreshToken(String refreshToken) throws SdkException;

    boolean isCxWebServiceAvailable();
}
