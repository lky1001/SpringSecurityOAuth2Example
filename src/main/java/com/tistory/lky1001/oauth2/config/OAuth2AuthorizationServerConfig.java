package com.tistory.lky1001.oauth2.config;

import com.tistory.lky1001.oauth2.security.CustomUserDetailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.token.DefaultToken;
import org.springframework.security.core.token.Token;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.*;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String SPARKLR_RESOURCE_ID = "testestsetsetset";

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.withClientDetails(clientDetailsService());
//        // @formatter:off
//        clients.inMemory().withClient("testestsetsetset")
//            .resourceIds(SPARKLR_RESOURCE_ID)
//            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
//            .authorities("ROLE_USER")
//            .scopes("read", "write")
//            .secret("secret")
//            .redirectUris("http://localhost:8080/home");
//        // @formatter:on
    }

    @Bean
    public ClientDetailsService clientDetailsService() {
        return new ClientDetailsService() {
            @Override
            public ClientDetails loadClientByClientId(String clientId)
                    throws ClientRegistrationException {

                ClientDetails clientDetails = new ClientDetails() {

                    @Override
                    public String getClientId() {
                        return clientId;
                    }

                    @Override
                    public Set<String> getResourceIds() {
                        Set<String> resourceIds = new HashSet<>();
                        resourceIds.add(SPARKLR_RESOURCE_ID);
                        return resourceIds;
                    }

                    @Override
                    public boolean isSecretRequired() {
                        return true;
                    }

                    @Override
                    public String getClientSecret() {
                        return "secret";
                    }

                    @Override
                    public boolean isScoped() {
                        return true;
                    }

                    @Override
                    public Set<String> getScope() {
                        Set<String> scopes = new HashSet<>();
                        scopes.add("read");
                        scopes.add("write");
                        return scopes;
                    }

                    @Override
                    public Set<String> getAuthorizedGrantTypes() {
                        Set<String> grantTypes = new HashSet<>();
                        grantTypes.add("password");
                        grantTypes.add("authorization_code");
                        grantTypes.add("refresh_token");
                        grantTypes.add("implicit");
                        return grantTypes;
                    }

                    @Override
                    public Set<String> getRegisteredRedirectUri() {
                        return null;
                    }

                    @Override
                    public Collection<GrantedAuthority> getAuthorities() {
                        return Arrays.asList(new GrantedAuthority() {
                            @Override
                            public String getAuthority() {
                                return "ROLE_USER";
                            }
                        });
                    }

                    @Override
                    public Integer getAccessTokenValiditySeconds() {
                        return 60 * 60;
                    }

                    @Override
                    public Integer getRefreshTokenValiditySeconds() {
                        return 60 * 60 * 24 * 14;
                    }

                    @Override
                    public boolean isAutoApprove(String scope) {
                        return false;
                    }

                    @Override
                    public Map<String, Object> getAdditionalInformation() {
                        return null;
                    }
                };

                return clientDetails;
            }
        };
    }

    @Bean
    public TokenStore tokenStore() {
        return new InMemoryTokenStore();
    }

    @Autowired
    private CustomUserDetailService userDetailService;

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.tokenStore(tokenStore)
            .authenticationManager(authenticationManager)
            .userDetailsService(userDetailService);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.realm("sparklr2/client");
    }
}
