# springboot-sec-tutor
---
## Introduction
This guide covers the security concerns about RESTful-backed applications. Spring boot is used to show example backend implementations of these concerns. Client implementations are not covered, yet in most cases this will be the browser and therefore this guide covers browser defenses.

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
- Scalable (extra Loadbalancer required)

#### Cons
- Java SSL implementation (not easily or not configurable at all, e.g. custom DHparams in Java 1.8)
- Keystore file instead of pem/crt/key files

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

*TODO*

## Authentication (who you are)
*TODO*

## Authorization (what are you allowed to do)
*TODO*

## HTTP Security Headers (Browsers defenses)
*TODO*
