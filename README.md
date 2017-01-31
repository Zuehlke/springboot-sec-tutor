This branch describes and implements a custom REST Authentication Login. Refer to [master branch](https://github.com/Zuehlke/springboot-sec-tutor/tree/master) for the guide through spring boot security.

# REST Authentication Login (Cookie Session-ID)
This is recommended when you use spring boot as a backend service only. It requires some caution when implementing it.
Meaning CSRF prevention may have to be dealt with by yourself.

## CSRF prevention
There are more than one strategy that you can choose from to prevent CSRF (see https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet). Spring uses the "Synchronizer Token" per default. This is also used in the Formlogin above. But since we can't render the Token with spring into a form we must find another way to prevent CSRF attacks.

The easiest way for that is to use spring's `CookieCsrfTokenRepository` with `csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())` which implements the "Double Submit Cookie" strategy and works as default with AngularJS and therefore is a really nice solution. Be aware that your frontend and backend must have the same Origin, if you have different Origins for the frontend and backend the frontend will not be able to read the backend Cookies through `document.cookie` even if you configured CORS. The Cookies will follow SoP (Same-origin Policy) (see https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/withCredentials).
If the Origins differ you have to correctly configure CORS (see CORS chapter) and implement a custom `CsrfTokenRepository` or your own `@RestController` (with e.g. /hello) which provides the Session-Token in a Header (but only in CORS-aware requests! Else you are not safe at all). 

In this branch [rest-auth](https://github.com/Zuehlke/springboot-sec-tutor/tree/rest-auth) there is an implementation of "having a custom header" which need some Filters to be implemented but fits pretty good for a pure backend (no token handling and Origin of frontend doesn't have to be the same).
For this we have to carefully configure CORS first. It needs to be done anyway to make your REST backend work with your frontend if the Origins differ!
When we know CORS is configured correctly we need to make sure that all the request are not simple requests. Relying on CORS we know that if a custom header is present (e.g. X-Requested-With) the browser will either not make the response accessible or will preflight the request (for details see https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS and https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Protecting_REST_Services:_Use_of_Custom_Request_Headers).
To ensure browser's requests are CORS-aware this Header is required to be present for every request and therefore need a custom Filter `XRequestedWithHeaderFilter`:

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    String header = request.getHeader("X-Requested-With");
    if(header == null || header.isEmpty()){
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,"X-Requested-With Header is not present or empty");
    } else {
        filterChain.doFilter(request, response);
    }
}

```
On the client side the header has to be added to every AJAX request. In AngularJS you can use [$httpProvider#defaults](https://code.angularjs.org/1.4.10/docs/api/ng/provider/$httpProvider#defaults) for that.
The OWASP article suggests to check Origin and Referer Header to prevent some exotic attacks with Flash. The Origin header is already checked (if present) by spring CORS handling and in case if it doesn't match the request is rejected (controller code not executed). Since in our case all request (done by instances of XMLHttpRequest) should have an Origin header we are going to implement a Filter, that denies all requests without the Origin header, called `EnforceCorsFilter`:

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    if (!CorsUtils.isCorsRequest(request)) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Not a CORS request (Origin header is missing)");
    } else {
        filterChain.doFilter(request, response);
    }
}
```

Now disable the default CSRF handling with `csrf().disable()` and add the Filters to the FilterChain in your `WebSecurityConfigurerAdapter` at the right position (before CsrfFilter is just fine).

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .csrf().disable()
            .addFilterBefore(new XRequestedWithHeaderFilter(), CsrfFilter.class)
            .addFilterBefore(new EnforceCorsFilter(), CsrfFilter.class);
}
```

## Custom authentication (REST) service

Now we should be save against CSRF attacks. But we haven't implemented the authentication service yet. This doesn't rely on one of the implemented "CSRF prevention".

We will use `HttpStatusEntryPoint` as `AuthenticationEntryPoint` and implement our own `AbstractAuthenticationProcessingFilter`. For the Filter there is a `ObjectMapper` required for deserialization `LoginRequestPOJO` of the login request's JSON body. Furthermore spring's `UsernamePasswordAuthenticationToken` is used to represent the `Authentication`.
The authentication has to be done with a POST request to /login. 

```java
public class RESTAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper;

    public RESTAuthenticationFilter(ObjectMapper objectMapper) {
        super(new AntPathRequestMatcher("/login", "POST"));
        this.objectMapper = objectMapper;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        LoginRequestPOJO loginRequestPOJO;
        try {
            loginRequestPOJO = objectMapper.readValue(request.getReader(), LoginRequestPOJO.class);
        } catch (JsonMappingException | JsonParseException e) {
            throw new AuthenticationServiceException("Invalid login request");
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
                loginRequestPOJO.getUsername(), loginRequestPOJO.getPassword());

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        return this.getAuthenticationManager().authenticate(authRequest);
    }
}
```
The default login success behavior of `AbstractAuthenticationProcessingFilter` is `SavedRequestAwareAuthenticationSuccessHandler` (which returns 302 Found for successfull logins) is replaced with a custom (200 OK) implementation of `AuthenticationSuccessHandler`:

```java
@Component
public class RESTAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_OK);
    }
}
``` 

You might also want to change the default logout behavior which also returns 302 for successfull logins. We can do this pretty simple with `logout().logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK))` in the `WebSecurityConfigurerAdapter`.

Well all of this doesn't yet make sense if it is not wired together somehow. This is done in `WebSecurityConfigurerAdapter`:

```java
@Autowired
private RESTAuthenticationSuccessHandler restAuthenticationSuccessHandler;

@Autowired
private AuthenticationManager authenticationManager;

@Autowired
private ObjectMapper objectMapper;

@Bean
public RESTAuthenticationFilter restAuthenticationFilter() {
    RESTAuthenticationFilter restAuthenticationFilter = new RESTAuthenticationFilter(objectMapper);
    restAuthenticationFilter.setAuthenticationManager(authenticationManager);
    restAuthenticationFilter.setAuthenticationSuccessHandler(restAuthenticationSuccessHandler);
    return restAuthenticationFilter;
}

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and().exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            .and().anonymous().disable()
            .csrf().disable()
            .addFilterBefore(new XRequestedWithHeaderFilter(), CsrfFilter.class)
            .addFilterBefore(new EnforceCorsFilter(), CsrfFilter.class)
            .addFilterBefore(restAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
            .logout().logoutSuccessHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK));
}
```

## Pros
- No form rendering
- No Token handling
- Frontends can have different Origins

## Cons
- No default implementation by spring

Be careful when implementing your REST services. If you for example change state with a GET, HEAD or OPTIONS request the security may be compromised (this also applies to non-persistent state like session-state).

If you don't want to use Cookies as session identifier store you have to either include spring-session (see http://docs.spring.io/spring-session/docs/current/reference/html5/guides/boot.html) and e.g. use HeaderHttpSessionStrategy or you could implement another AuthenticationFilter to check the request for the valid Token (you might also think about disabling the creation of sessions with `sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)` if you have a custom AuthenticationFilter and don't need any other server (session) state). But be careful since cookies have securing mechanisms like secure, httpOnly, max-age etc. which you can't enforce when using another browser persistency mechanism.
