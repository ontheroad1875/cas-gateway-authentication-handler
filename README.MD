CAS UNPROTECTED PAGE AUTHENTICATION HANDLER
===========================================

This filter aims to add the gateway functionality in a spring security filter. By using the CasUnprotectedPageAuthenticationFilter, users can start authentication process in an unprotected page (anonymous page).

CONFIGURATION
=============

Add the maven dependency:

```maven
<dependency>
   <groupId>br.com.softplan.unj</groupId>
   <artifactId>cas-unprotected-page-authentication-handler</artifactId>
   <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Configure the filterChain to add the filter after the FilterSecurityInterceptor:

```java
@Configuration
@EnableWebSecurity
public class CasClientConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        ... Other configurations
        http
            .addFilterAfter(casUnprotectedPageFilter(), FilterSecurityInterceptor.class)

        ...other configurations
    }

    //Beans needed to configure cas

}
```

Configure the CasAuthenticationFilter:

You need to set the authenticationFailureHandler and the authenticateSuccessHandler using the AuthenticationHandler

```java
@Bean
AuthenticationHandler authenticationHandler() {
    return new GatewayAwareUrlAuthenticationHandler();
}

@Bean
CasAuthenticationFilter casProcessingFilter() throws Exception {
   CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
   casAuthenticationFilter.setAuthenticationFailureHandler(authenticationHandler());
   casAuthenticationFilter.setAuthenticationSuccessHandler(authenticationHandler());
   return casAuthenticationFilter;
}
```

REQUIREMENTS
================================

- The cas authentication cookie (TGC or whatever name you changed) has to have the path set to "/"
- When configuring the CasUnprotectedPageAuthenticationFilter you have to set the name of the cas cookie. 
  By default it uses TGC.

