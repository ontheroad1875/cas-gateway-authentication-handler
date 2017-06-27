Cas gateway authentication handler
===========================================

This project aims to add the gateway functionality in a spring security filter. By using the CasGatewayAuthenticationFilter, users can start authentication process in an unprotected resource (anonymous resource).

Configuration
=============

Add the maven dependency:

NOT DEPLOYED TO MAVEN CENTRAL.

```maven
<dependency>
            <groupId>br.com.softplan</groupId>
            <artifactId>cas-gateway-authentication-handler</artifactId>
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
            .addFilterAfter(casUnprotectedResourceFilter(), FilterSecurityInterceptor.class)

        ...other configurations
    }

    @Bean
    Filter casUnprotectedResourceFilter() {
        return new CasUnprotectedResourceAuthenticationFilter(casEntryPoint());
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



You can define the strategy to determine if the user is logged in and if the filter 
should try to start authentication. An example:

```java

public class CustomStrategy implements AuthenticationVerifierStrategy {

   ... implementation

}

@Bean 
CustomStrategy customStrategy() {
    return new CustomStrategy();
}

@Bean
Filter casUnprotectedResourceFilter() {
    return new CasUnprotectedResourceAuthenticationFilter(casEntryPoint(), customStrategy());
}
```


The default strategy is the VisibleAuthenticationCookieStrategy, 
this strategy expects that the TGC cookie from cas is visible to all applications it 
should to authenticate (only works when in the same domain)

You can change the cas cookie name instatiating the VisibleAuthenticationCookieStrategy 
and passing in the constructor. By default the cookie name is TGC. 

```java

@Bean
AuthenticationVerifierStrategy visibleAuthenticationCookieStrategy() {
    return new VisibleAuthenticationCookieStrategy(CAS_AUTHENTICATION_COOKIE_NAME);
}

```


