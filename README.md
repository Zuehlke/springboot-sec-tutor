# springboot-sec-tutor
---
## Introduction
This guide covers the security concerns about RESTful-backed applications. Spring boot is used to show example backend implementations of these concerns. Client implementations are not covered, only described. Furthermore guide covers browser defenses that should be implemented.

## Transport Layer
First to think about is whether to use SSL and for what services to use it (e.g. static resources). SSL should always be used when your application involves authentication. Hence at least your authentication process and the restricted part of the application should be restricted to SSL (HTTPS) connections only. The reason is pretty obvious: Prevention of account- and session-hijacking through man-in-the-middle attacks.

As you will probably always require SSL for at least some services of your application. The question is where to implement it. Therefore there are some examples with pros and cons:

### HTTP Server (apache, nginx, ...)
In most cases the SSL implementing part is the HTTP server you front your application with. Be sure to use the latest OpenSSL version!
#### Pros
- Easy implementation
- Configuration
- Scalable
- Most up-to-date SSL implementations

#### Cons
- Not truly end-to-end (The traffic between HTTP server and your application (servlet container) might be unencrypted)

### Servlet Container (Tomcat, Jetty, ...)
This is unusual but can be done. Example implementation and current secure configuration using embedded tomcat can be found in this repository.
#### Pros
- Truly end-to-end encryption

#### Cons
- Configuration. Java SSL implementation (not easily or not configurable at all, e.g. custom DHparams in Java 1.8)
- Keystore file instead of pem/crt/key files
- Scalability complicated (extra Loadbalancer required. Also certificate must be n-times deployed)

### Cloud (AWS) *cloud enviroment*
Mostly the SSL is terminated on the Loadbalancer. AWS lets you create signed certificate (in ACM) and add it to your LB/CloudFront or upload your own signed certificate to IAM and refer it in your LB/CloudFront.
#### Pros
- Easy SSL implementation
- Scalable

#### Cons
- Not truly end-to-end if terminated on LB (see [http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/configuring-https-endtoend.html])
- Configuration. Not fine grained: You can choose from predefined set of SSL Security Policies

### SSL configuration
Now that the implementing part is known, the question is what to consider a secure SSL config. Therefore you want to check the following sites:
- [https://mozilla.github.io/server-side-tls/ssl-config-generator/] suggesting to use modern configuration (see for details and configure ciphers as wanted/required [https://wiki.mozilla.org/Security/Server_Side_TLS])
- [https://weakdh.org/] if you use DH cipher then you should consider creating your own DHparams since the default are weak (this is only required if you use a DHE- cipher not for ECDHE- therefore you don't have to do this if you use 'modern' config above). Also check [https://weakdh.org/sysadmin.html] for creating/deploying customn DHparams.pem to your HTTP server.
- [https://drownattack.com/] disable SSLv2 since its vulnerable to the DROWN attack. Instructions for some HTTP server can be found on the site.
- [https://en.wikipedia.org/wiki/POODLE] disable SSLv3 since its vulnerable to the POODLE attack.
- [https://en.wikipedia.org/wiki/CRIME_(security_exploit)] disable SSL compression since it is vulnerable to th CRIME attack (and others). For confiuration refer to your HTTP server documentation.
- [http://breachattack.com/] disable HTTP compression since it is vulnerable to oracle attacks (e.g. BREACH). This is mostly default in the Servlet Containers. Don't enable it!

For apache documentation refer to:
- [http://httpd.apache.org/docs/trunk/ssl/ssl_howto.html] example apache ssl configuration (including TSLv1.2 only, SSLCompression, SSLHonorCipherOrder, SSLSessionTickets)

For AWS LB HTTPS configuration refer to:
- [http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-add-or-delete-listeners.html] how to add a certificate to you LB
- [http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html] ssl configuration

### SSL security check **Important**!
Once the configuration is done and you think you did everything right, its time to face the truth. Deploy your app and check your ssl configuration with [https://www.ssllabs.com/ssltest/]. Fix configuration until you have at least an A mark (or better A+).

## Authentication (who you are)
Most applications need authorization (what is who allowed to do). Authentication is precondition for authorization since you need to make sure who the application is interacting with. 
There are different ways to implement authentication in spring boot, each having their pros and cons.

### Fromlogin (Cookie Session-ID)
The most common and easiest to use solution. Implementation can be found in the master branch. The relevant part is the code in the *WebSecurityConfigurerAdapter*

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .logout().permitAll();
    }
```

The `formLogin()` does it all. This means that the form will be rendered by spring boot (default login template). If you want to have another template you can specify it with `loginPage("/login")` and have a View "login" configured (see [http://docs.spring.io/spring-security/site/docs/current/guides/html5/form-javaconfig.html#configuring-a-custom-login-page] for details).
If you plan to use the spring boot app only as backend then its recommend to use **REST Authentication Login**. Why? Well because else it results in having to deal with the CSRF-TOKEN by yourself.
Therefore if you have a correctly configured CORS configuration (see HTTP Security Headers) you could have an extra `@RestController` which provides the Token in a Header. You can access the CSRF-Token with `request.getAttribute(CsrfToken.class.getName())` (requires `CsrfFilter` to be enabled, which is default in spring boot). **DO NOT DISABLE CSRF IF YOU HAVE A FORM LOGIN**

#### Pros
- Easy to configure

#### Cons
- Requires spring to render CSRF-Token or handle defense manually

### REST Authentication Login (Cookie Session-ID)
This is recommended when you use spring boot as a backend service only. An example implementation can be found in the *rest-auth* branch. It requires some caution when implementing it.

#### CSRF prevention
There are more than one strategy that you can choose from to prevent CSRF (see [https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet]). We will cover the having a custom header which fits the needs best for a pure backend (no token handling). Be aware that if you use AngularJS you can use spring's `CookieCsrfTokenRepository` which implements the "Double Submit Cookie" strategy and works as default with AngularJS.

First of all we have to carefully configure CORS (see HTTP Security Headers) which we will need to do anyways!
When we know CORS is configured correctly we need to make sure that all the request are not simple requests. Relying on CORS we know that if a custom header is present (e.g. X-Requested-With) the browser will either not make the response accessible or will preflight the request (for details see [https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS] and [https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Protecting_REST_Services:_Use_of_Custom_Request_Headers]).
We need to make sure that this Header is present for every request and therefore need a custom Filter: *TODO*

As suggested by the OWASP article we also have to check the Origin and Referer Header to prevent some exotic attacks with Flash. *TODO*

#### Custom authentication (REST) service

Now we should be save agains CSRF attacks. But we haven't implemented the authentication service yet. For that we will need custom implementations of *AuthenticationEntryPoint* and *AbstractAuthenticationProcessingFilter* *TODO*

Be careful when implementing your REST services. If you for example change state with a GET request the security may be compromised.

If you don't want to use Cookies as session identifier store you have to either include spring-session (see [http://docs.spring.io/spring-session/docs/current/reference/html5/guides/boot.html]) and use HeaderHttpSessionStrategy or you could implement your own AuthenticationFilter to check the request for the valid Token (you might also think about disabling the creation of sessions with `sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)` if you have a custom AuthenticationFilter and don't need any other server (session) state). But be careful since cookies have securing mechanisms like secure, httpOnly, max-age etc. which you can't enforce when using another browser persistency mechanism.

---

## Authorization (what are you allowed to do)
*TODO*

---

## Data storage
*TODO*

---

## HTTP Security Headers (Browsers defenses)
*TODO*
