package com.zuehlke.bgre.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                // Security Headers http://docs.spring.io/spring-security/site/docs/current/reference/html/headers.html
                .headers()
                    // Cache-Control: no-cache set by default spring boot security
                    //.cacheControl()
                    //.and()
                    // X-Frame-Options: DENY set by default spring boot security
                    .frameOptions().sameOrigin()
                    // X-Content-Type-Options: nosniff set by default spring boot security
                    //.contentTypeOptions()
                    //.and()
                    // Content-Security-Policy
                    .contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp")
                // HSTS (you may consider setting this header in the ssl handling part of your app e.g. apache, nginix)
                .and()
                    // be careful when deploying this 2 years policy because it will prevent your customers browsers from visiting your page without ssl
                    .httpStrictTransportSecurity()
                    .maxAgeInSeconds(63072000)
                // HPKP (you may consider setting this header in the ssl handling part of your app e.g. apache, nginix)
                .and()
                    .httpPublicKeyPinning()
                    .addSha256Pins("pGO1ErsUFSrId1hozlZOfyYOsE8mdiDgLyR89CtHK8E=")
                    .maxAgeInSeconds(63072000)
                    // remove reportOnly when certificates (including backup certificates!) including thoughtfully made deployment strategy worked out
                    .reportOnly(true)
                    .reportUri("/pkp");
    }
}
