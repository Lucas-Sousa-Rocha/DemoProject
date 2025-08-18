package com.quantum.demoproject.DTO;

public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;

    public TokenResponse() {}

    public TokenResponse(String access, String refresh) {
        this(access, refresh, "Bearer");
    }

    public TokenResponse(String access, String refresh, String type) {
        this.accessToken = access;
        this.refreshToken = refresh;
        this.tokenType = type;
    }

    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }

    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
}
