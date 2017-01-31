# springboot-sec-tutor

## Table of content
- Introduction
- Transport Layer
- Authentication (who you are)
- Authorization (what are you allowed to do)
- Data security
- CORS (Cross-Origin Resource Sharing)
- HTTP Security Headers (Browsers defenses)
- Cookie Security

---

## [Introduction](#introduction)
This guide covers the security concerns about RESTful-backed applications. Spring boot is used to show example backend implementations of these concerns. Client implementations are not covered, only described. Furthermore this guide covers browser defenses that should be implemented/configured.

## [Transport Layer](#transport-layer)
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
- Not truly end-to-end if terminated on LB (see [AWS ELB End-to-End](http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/configuring-https-endtoend.html))
- Configuration. You can choose from predefined set of SSL Security Policies or configure it via command line or JSON (see [SSL config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/) and choose AWS LB)

### SSL configuration
Now that the implementing part is known, the question is what to consider a secure SSL config. Therefore you want to check the following sites:
- https://mozilla.github.io/server-side-tls/ssl-config-generator/ suggesting to use modern configuration (see for details and configure ciphers as wanted/required [Mozilla Cipher List](https://wiki.mozilla.org/Security/Server_Side_TLS))
- https://weakdh.org/ if you use DH cipher then you should consider creating your own DHparams since the default are weak (this is only required if you use a DHE- cipher not for ECDHE- therefore you don't have to do this if you use 'modern' config above). Also check [weakdh.org sysadmin guide](https://weakdh.org/sysadmin.html) for creating/deploying customn DHparams.pem to your HTTP server.
- https://drownattack.com/ disable SSLv2 since its vulnerable to the DROWN attack. Instructions for some HTTP server can be found on the site.
- https://en.wikipedia.org/wiki/POODLE disable SSLv3 since its vulnerable to the POODLE attack.
- https://en.wikipedia.org/wiki/CRIME_(security_exploit) disable SSL compression since it is vulnerable to th CRIME attack (and others). For confiuration refer to your HTTP server documentation.
- http://breachattack.com/ disable HTTP compression since it is vulnerable to oracle attacks (e.g. BREACH). This is mostly default in the Servlet Containers. Don't enable it!

For apache documentation refer to:
- http://httpd.apache.org/docs/trunk/ssl/ssl_howto.html example apache ssl configuration (including TSLv1.2 only, SSLCompression, SSLHonorCipherOrder, SSLSessionTickets)

For AWS LB HTTPS configuration refer to:
- http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-add-or-delete-listeners.html how to add a certificate to you LB
- http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html ssl configuration

### SSL security check **Important**!
Once the configuration is done and you think you did everything right, its time to face the truth. Deploy your app and check your ssl configuration with https://www.ssllabs.com/ssltest/. Fix configuration until you have at least an A mark (or better A+).

## [Authentication (who you are)](#authentication)
Most applications need authorization (what is who allowed to do). Authentication is precondition for authorization since you need to make sure who the application is interacting with. 
There are different ways to implement authentication in spring boot, each having their pros and cons.

### Fromlogin (Cookie Session-ID)
The most common and easiest to use solution. Implementation can be found in the master branch. The relevant part is the code in the `WebSecurityConfigurerAdapter`

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

The `formLogin()` does it all. This means that the form will be rendered by spring boot (default login template). If you want to have another template you can specify it with `loginPage("/login")` and have a View "login" configured (see http://docs.spring.io/spring-security/site/docs/current/guides/html5/form-javaconfig.html#configuring-a-custom-login-page for details).
If you plan to use the spring boot app only as backend then I recommend to use **REST Authentication Login**. Why? Well because else it results in having to deal with the CSRF-TOKEN by yourself.
**DO NOT DISABLE CSRF IF YOU HAVE A FORM LOGIN LIKE THIS**

#### Pros
- Easy to configure (everything implemented by spring)

#### Cons
- Requires spring to render CSRF-Token or handle defense manually

### REST Authentication Login (Cookie Session-ID)
This is recommended when you use spring boot as a backend service only. An example implementation and its description can be found in the [rest-auth](https://github.com/Zuehlke/springboot-sec-tutor/tree/rest-auth) branch. 

### JWT
We first have to look into JWT a bit. JWT is a signed Token and therefore can be checked by the signing party if it has originally signed it. 
So when we use JWT for Authentication the server issues signed tokens and sends it to the client (browser) which has to store it. The server normally can forget about the issued tokens. Everytime when the client now sends this JWT token with a request, the server can check if it has issued this token. But this means the complete session state is transfered with every request.
Also if the server forgets about the issued tokens then they can't be revoked. You can find a lot of example implementations on the internet. **But** there is no good reason to use JWT's as session mechanism ([check out this article reasoning why](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/)).
We agree with this reasoning and therefore will not cover an example implementation but only describe an example of a reasonable use case: *Single-use authorization token*: The actual authentication has nothing to do with JWTs.
The use case could look like this:
As a registered and authenticated user I want to issue an invitation so that another user can register. The given roles at the registration have to be fixed by the registered user.

Having a JWT here is convenient: It contains the claims (right to register, roles) and an expiration date. The server can completely forget about this token (no state required). The token should be short-lived. To make sure it is only used once the email or another user-unique value could be saved in the token.

---

## [Authorization (what are you allowed to do)](#authorization)
There are different ways to implement authorization. Here we will cover the role based authorization. If you want to have another type of access controll (authorization) then you can either implement your own `AccessDecisionManager` or an `AccessDecisionVoter` (see http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#tech-intro-access-control).

We can control which role can invoke which methods or call which URLs.
The implementation of a domain model containing `Role` can be found in this repository. In our case users can have multiple roles and therefore is modeled as a many-to-many relationship and our role model is not hierarchical. Therefore one role (e.g. ADMIN) doesn't contain another role (e.g. USER).

There are two ways to restrict the access for a specific role (or multiple roles):
- Spring security configuration `WebSecurityConfigurerAdapter` 
	```java
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
			.antMatchers("/users/**").hasRole("USER")
			.and()
			// ....
	}
	``` 

	This will restrict the access for URL /users/** to users with the "ROLE_USER" authority. Be aware that this is invoked (and therefore blocked) before any of the Controllers code and even maybe some of your Filters. So you can't generally restrict access here and relax it somewhere else.
- Method based access control (Annotations)
	You have to enable global method security with the annotation `@EnableGlobalMethodSecurity(prePostEnabled = true)` in one of your `@Configuration`s (preferably in `WebSecurityConfigurerAdapter`). After that you can use `@PreAuthorize` or `@PostAuthorize` on class- and method-level with Spring EL to control access. This controller is restricted to users with "ROLE_USER" but it contains a method that is restricted for users with "ROLE_ADMIN" only.
	```java
	@RestController
	@RequestMapping("/users")
	@PreAuthorize("hasRole('USER')")
	public class UserController {
		@Autowired
		private UserService userService;

		@PreAuthorize("hasRole('ADMIN')")
		public List<UserDTO> getUsers() {
			// ...
		}
	}
	```

### OAuth2
When you implement an resource server and the authentication (and optionally authorization) is done by a different application then mostly OAuth2 is considered as solution. There are plenty of example implementations on the internet to find (e.g. https://spring.io/guides/tutorials/spring-boot-oauth2/) and that's why we will not cover an implementation.

---

## [Data security](#data-security)

### Passwords
There is at least some part of data that should be secured by your application: Passwords. For this you should use a cryptographic hash function. Check [OWASP Password Storage Cheat Sheet](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and decide on which one-way function to use.
In this repository we use bcrypt. You can implement your own `PasswordEncoder` (e.g. using Argon2 Library (currently only bindings for JVM exists)). Spring includes a few implementations of `PasswordEncoder` like `BCryptPasswordEncoder`, `SCryptPasswordEncoder` or `Pbkdf2PasswordEncoder`.
We create a new `@Configuration` which defines the `PasswordEncoder` as a Bean (Note: you can replace `BCryptPasswordEncoder` with any implementation of `PasswordEncoder`).

```java
@Configuration
public class PasswordEncoderConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```
You could also include this code into your `WebSecurityConfigurerAdapter`.
Next we will use this `Bean` in the `WebSecurityConfigurerAdapter` to tell our `UserDetailsService` to use the encoder.

```java
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
}
```

### Encryption
If you need to save data encrypted (and e.g. prompt user for password to decrypt) then you can implement your own `BytesEncryptor` or use one of springs included (e.g. `AesBytesEncryptor`). Springs helper class `Encryptors` can be used for convenience (e.g. `Encryptors.delux(dataToSecure, salt)`).
*Note:* You might need to download and install [JCE](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) (link for Java 1.8).
This repository does **NOT** contain any implementation to save encrypted data.

---

## [CORS (Cross-Origin Resource Sharing)](#cors)
CORS was introduced to relax the SoP which prevents requests made by a script (e.g. AJAX request) that has been loaded by `www.a.com` to a backend `www.b.com`. So if the Origins of your frontend(s) and backend differ you have to configure CORS anyway because else browsers will block these calls. First you exactly want to know what CORS is and what headers it includes: https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS

Allright, so there are 2 ways to configure CORS in spring. You should combine both.
1. Global CORS configuration
	```java
	@Configuration
	public class GlobalCorsConfig extends WebMvcConfigurerAdapter {
		@Override
		public void addCorsMappings(CorsRegistry registry) {
			registry.addMapping("/**")
				.allowedOrigins("http://myurl.com")
				.allowedMethods("GET", "POST");
		}
	}
	```
	This will be your general CORS configuration which spring will combine with following rules found for the request:
2. Annotation-based CORS configuration (fine-grained)
	```java
	@CrossOrigin(origins = "http://myfrontend.com", methods = {RequestMethod.GET, RequestMethod.POST}, allowCredentials = "true", maxAge = 3600)
	```
	can be used on class- and method-level in your controllers. 


Actually there is a 3rd way to configure CORS (Filter). You can have a look at http://docs.spring.io/spring/docs/current/spring-framework-reference/html/cors.html if you figure its necessary to use the Filter.

---

## [HTTP Security Headers (Browsers defenses)](#http-security-headers)
There are some HTTP Headers (set by your application) to control some security mechanisms of your user's browsers. Spring boot sends most of them per default and therefore provides a good basic security. We will quickly go through these headers and show how to enable/configure them in the `WebSecurityConfigurerAdapter`.
Refer to http://docs.spring.io/spring-security/site/docs/current/reference/html/headers.html to discover all possibilities.

### Cache-Control
Cache-Control header will advice the browser if the page should be cached. Usually you want to turn off the cache to prevent unauthorized attackers to access this cache through the browser history. Spring security disables the cache as default.

### X-Content-Type-Options
This header controls the browsers capability of guessing a resource's Content-Type. This feature should be disabled to prevent some attacks (e.g. XSS in image meta-data). Spring security disables content sniffing as default.

### Strict-Transport-Security
HSTS prevents the browsers to connect to this domain without SSL. Suggestion: Implement this header where you terminate your SSL connection (e.g. if you use HTTP Server like nginx your should adivce nginx to add this header instead of using spring to add it. Reason: single responsibility principle). If spring recognizes that the embedded servlet container only serves HTTPS this header is added automatically with some default values:
`Strict-Transport-Security: max-age=31536000 ; includeSubDomains`

To enable and ajust the HSTS you can use `headers().httpStrictTransportSecurity().maxAgeInSeconds(63072000).includeSubDomains(true)`. Unfortunately the requirements for the preload list is to have `preload` directive in the header (see https://hstspreload.org/) which cannot be added this way.

**Be very careful when deploying this header: Browser will save this and you can't undo it.**
### Public-Key-Pins
If for some reason your trust in CAs doesn't meet the requirements or you absolutely want to make sure that only a specific certificate is accepted by your client's browsers, then use HPKP. There are not too many good reasons to use HPKP (see https://blog.qualys.com/ssllabs/2016/09/06/is-http-public-key-pinning-dead)! But if you know what you are doing and want to enable HPKP (which you should again only do in spring if you terminate the SSL connection in the embedded servlet container like HSTS), then you can do it like this:
```java
headers().
	.httpPublicKeyPinning()
	.addSha256Pins("pGO1ErsUFSrId1hozlZOfyYOsE8mdiDgLyR89CtHK8E=")
	.maxAgeInSeconds(63072000)
	.reportOnly(true)
	.reportUri("/pkp")
	.includeSubDomains(true);
```
The `addSha256Pins` method takes a list of pins. The pins are actually base64-encoded-SHA256-hashed-DER-formatted Public-Keys so you can use

`openssl x509 -pubkey < tls.crt | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`

to create a pin (see https://scotthelme.co.uk/hpkp-http-public-key-pinning/ for details). You can pin any public key in the chain (e.g. CA's public key or intermediate certificate authority's public key).

There is an example implementation in this repository (pinning embedded servlet containers certificate's public key).

### X-Frame-Options
Restricts browsers from framing your site. Spring security disables the framing as default with `DENY`. You can relax this with e.g. `headers().frameOptions().sameOrigin()` as also done in the implementation of this repository.

### X-XSS-Protection
Controls the XSS protection mechanism of the browser. Be aware that the browser's XSS protection can only detect (and block) a few XSS attacks (many NOT!). Spring security enables this header as default:

`XSS-Protection: 1; mode=block`

Do not relax this unless you really have to do it. Then you can use `headers().xssProtection().block(false).xssProtectionEnabled(true)` to relax it.

### Content-Security-Policy
CSP allows you to control what content should be loaded/executed by the browsers. See https://content-security-policy.com/ for the directives and sources that can be configured. The CSP may depend on the content that was loaded by a request but spring security currently only assits you with the global configuration. So if you want to use Annotations in your `@Controller`s to control the CSP header you have to implement that by yourself.
For the global configuration use:

`headers().contentSecurityPolicy("default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp")`

## [Cookie Security](#cookie-security)
Spring security recognizes if the servlet container serves HTTPS and therefore marks the session cookie (JSESSIONID) as secure automatically. But if you terminate your SSL on e.g. apache then spring can't know if the request was served over an SSL tunnel. To set the 'secure' flag on the cookie add the following to your `application.properties`:

`server.session.cookie.secure=true`

You should alway make sure that the session cookie has flags 'httpOnly' and 'secure'!

*Hint:* All of the session cookie flags (domain, path, max-age, ...) can be configured through properties. See https://docs.spring.io/spring-boot/docs/current/reference/html/common-application-properties.html

---

That's it for this tutor!
