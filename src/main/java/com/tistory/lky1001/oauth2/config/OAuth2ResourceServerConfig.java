package com.tistory.lky1001.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableResourceServer
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private static final String SPARKLR_RESOURCE_ID = "testestsetsetset";

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(SPARKLR_RESOURCE_ID)
                .tokenStore(tokenStore());
    }

    public static class CustomOAuth2Request extends OAuth2Request {
        public CustomOAuth2Request(String clientId) {
            super(clientId);
        }
    }

    @Bean
    public TokenStore tokenStore() {
        return new TokenStore() {
            @Override
            public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
                OAuth2Request storedRequest = new CustomOAuth2Request(SPARKLR_RESOURCE_ID);
                storedRequest.getResourceIds().add(SPARKLR_RESOURCE_ID);

                OAuth2Authentication bizUserOauth2Authentication = new OAuth2Authentication(storedRequest, new Authentication() {

                    @Override
                    public String getName() {
                        return "melisa";
                    }

                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        return Arrays.asList(new GrantedAuthority() {
                            @Override
                            public String getAuthority() {
                                return "ROLE_USER";
                            }
                        });
                    }

                    @Override
                    public Object getCredentials() {
                        return "koala";
                    }

                    @Override
                    public Object getDetails() {
                        return new Object();
                    }

                    @Override
                    public Object getPrincipal() {
                        return "melisa";
                    }

                    @Override
                    public boolean isAuthenticated() {
                        return true;
                    }

                    @Override
                    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

                    }
                });

                return bizUserOauth2Authentication;
            }

            @Override
            public OAuth2Authentication readAuthentication(String token) {
                return null;
            }

            @Override
            public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {

            }

            @Override
            public OAuth2AccessToken readAccessToken(String tokenValue) {
                return new OAuth2AccessToken() {
                    @Override
                    public Map<String, Object> getAdditionalInformation() {
                        return null;
                    }

                    @Override
                    public Set<String> getScope() {
                        Set<String> scopes = new HashSet<>();
                        scopes.add("read");
                        return scopes;
                    }

                    @Override
                    public OAuth2RefreshToken getRefreshToken() {
                        return null;
                    }

                    @Override
                    public String getTokenType() {
                        return null;
                    }

                    @Override
                    public boolean isExpired() {
                        return false;
                    }

                    @Override
                    public Date getExpiration() {
                        return null;
                    }

                    @Override
                    public int getExpiresIn() {
                        return 0;
                    }

                    @Override
                    public String getValue() {
                        return tokenValue;
                    }
                };
            }

            @Override
            public void removeAccessToken(OAuth2AccessToken token) {

            }

            @Override
            public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {

            }

            @Override
            public OAuth2RefreshToken readRefreshToken(String tokenValue) {
                return null;
            }

            @Override
            public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
                return null;
            }

            @Override
            public void removeRefreshToken(OAuth2RefreshToken token) {

            }

            @Override
            public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {

            }

            @Override
            public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
                return null;
            }

            @Override
            public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
                return null;
            }

            @Override
            public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
                return null;
            }
        };
    }

//    @Bean
//    public ResourceServerTokenServices resourceServerTokenServices() {
//        return new ResourceServerTokenServices() {
//            @Override
//            public OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException {
//                OAuth2Request storedRequest = new CustomOAuth2Request(SPARKLR_RESOURCE_ID);
//
//                OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(storedRequest, new Authentication() {
//                    @Override
//                    public Collection<? extends GrantedAuthority> getAuthorities() {
//                        return Arrays.asList(new GrantedAuthority() {
//                            @Override
//                            public String getAuthority() {
//                                return "ROLE_USER";
//                            }
//                        });
//                    }
//
//                    @Override
//                    public Object getCredentials() {
//                        return "melisa";
//                    }
//
//                    @Override
//                    public Object getDetails() {
//                        return null;
//                    }
//
//                    @Override
//                    public Object getPrincipal() {
//                        return "koala";
//                    }
//
//                    @Override
//                    public boolean isAuthenticated() {
//                        return false;
//                    }
//
//                    @Override
//                    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
//
//                    }
//
//                    @Override
//                    public String getName() {
//                        return "melisa";
//                    }
//                });
//
//                return oAuth2Authentication;
//            }
//
//            @Override
//            public OAuth2AccessToken readAccessToken(String accessToken) {
//                return null;
//            }
//        };
//    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
            .headers()
            .frameOptions().disable()
            .and()
            .formLogin().disable()
            .httpBasic().disable()
            .csrf().disable()
            .exceptionHandling()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.NEVER)
            .and()
            .authorizeRequests()
            .antMatchers("/secure").access("hasRole('ROLE_USER')")
            .anyRequest().permitAll();
    }
}
