package com.tistory.lky1001.oauth2.config;

import com.tistory.lky1001.oauth2.security.CustomAuthenticationProvider;
import com.tistory.lky1001.oauth2.security.CustomOAuth2Provider;
import com.tistory.lky1001.oauth2.security.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;

@Configuration
public class GlobalSecurityConfig extends GlobalAuthenticationConfigurerAdapter {

    @Autowired
    private CustomOAuth2Provider customOAuth2Provider;

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Autowired
    CustomUserDetailService customUserDetailService;

    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider)
                .authenticationProvider(customOAuth2Provider)
                .userDetailsService(customUserDetailService);
    }

    public void configure(AuthenticationManagerBuilder auth) throws Exception {

    }
}
