# springboot-sec-tutor
---
## Introduction
This guide covers the security concerns about RESTful-backed applications. Spring boot is used to show example backend implementations of these concerns. Client implementations are not covered, yet in most cases this will be the browser and therefore this guide covers browser defenses.

## Transport Layer
First think to think about is whether to use SSL and for what services it should be used (e.g. static resources). SSL should always be used when your application involves authentication. Hence at least your authentication process and the restricted part of the application should be restricted to SSL (HTTPS) connections only. The reason is pretty obvious: Prevention of account- and session-hijacking through man-in-the-middle attacks.

As you will probably always require SSL for at least some services of your application. The question is where to implement it. Therefore there are some examples with pros and cons:

### HTTP Server (apache, nginx, ...)
In most cases the SSL implementing part is the HTTP server you front your application with.
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
- Scalable (extra Loadbalancer required)

#### Cons
- Java SSL implementation (not easily or not configurable at all, e.g. DHparams)
- Keystore file instead of pem/crt/key files

*TODO*

## Authentication (who you are)
*TODO*

## Authorization (what are you allowed to do)
*TODO*

## HTTP Security Headers (Browsers defenses)
*TODO*
