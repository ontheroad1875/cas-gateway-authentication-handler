package br.com.softplan.cas.client.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class GatewayAwareUrlAuthenticationHandlerTest {

	private GatewayAwareUrlAuthenticationHandler gatewayAwareUrlAuthenticationHandler = new GatewayAwareUrlAuthenticationHandler();

	private HttpServletRequest httpServletRequest;

	private HttpServletResponse httpServletResponse;

	private HttpSession sessionMock;

	private RequestCache requestCache;

	private RedirectStrategy redirectStrategy;

	private AuthenticationFailureHandler authenticationFailureHandler;

	private SavedRequest savedRequestMock;

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Before
	public void initializeTests() throws Exception {
		// Mocked request and response
		this.httpServletRequest = Mockito.mock(HttpServletRequest.class);
		this.httpServletResponse = Mockito.mock(HttpServletResponse.class);
		this.sessionMock = Mockito.mock(HttpSession.class);
		Mockito.when(this.httpServletRequest.getSession()).thenReturn(this.sessionMock);
		// Request cache
		this.requestCache = Mockito.mock(RequestCache.class);
		// Redirect strategy
		this.redirectStrategy = Mockito.mock(RedirectStrategy.class);
		// Authenticate Failure/Success handler
		this.authenticationFailureHandler = Mockito.mock(AuthenticationFailureHandler.class);
		this.authenticationSuccessHandler = Mockito.mock(AuthenticationSuccessHandler.class);
		// Initialize the concrete implementation
		this.gatewayAwareUrlAuthenticationHandler.setRequestCache(this.requestCache);
		this.gatewayAwareUrlAuthenticationHandler.setRedirectStrategy(this.redirectStrategy);
		this.gatewayAwareUrlAuthenticationHandler.setAuthenticationFailureHandler(this.authenticationFailureHandler);
		this.gatewayAwareUrlAuthenticationHandler.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
		// Saved Request
		this.savedRequestMock = Mockito.mock(SavedRequest.class);
		Mockito.when(this.requestCache.getRequest(this.httpServletRequest, this.httpServletResponse)).thenReturn(this.savedRequestMock);
		Mockito.when(this.savedRequestMock.getRedirectUrl()).thenReturn("/cached");

		this.gatewayAwareUrlAuthenticationHandler.afterPropertiesSet();
	}

	@Test
	public void authenticateFailsOnAGatewayRequestWithCachedRequest() throws IOException, ServletException {
		gatewayRequest();
		this.gatewayAwareUrlAuthenticationHandler.onAuthenticationFailure(this.httpServletRequest, this.httpServletResponse, null);
		notCallingTheAuthenticationFailureHandler();
		redirectToCachedRequest();
	}

	@Test
	public void authenticateFailsOnAGatewayRequestWithoutCachedRequest() throws IOException, ServletException {
		gatewayRequest();
		noRequestCached();
		this.gatewayAwareUrlAuthenticationHandler.onAuthenticationFailure(this.httpServletRequest, this.httpServletResponse, null);
		defaultUrlFailureHandlerAfterRequestCacheCheck();
	}

	@Test
	public void authenticateFailsNotOnAGatewayRequest() throws IOException, ServletException {
		this.gatewayAwareUrlAuthenticationHandler.onAuthenticationFailure(this.httpServletRequest, this.httpServletResponse, null);
		noCallToRedirectOrRequestCache();
		delegatedToAuthenticationFailureHandler();
	}

	@Test
	public void authenticateSuccessOnAGatewayRequest() throws IOException, ServletException {
		gatewayRequest();
		this.gatewayAwareUrlAuthenticationHandler.onAuthenticationSuccess(this.httpServletRequest, this.httpServletResponse, null);
		removedSessionAttribute();
		delegateToAuthenticationSuccessHandler();
	}

	@Test
	public void authenticateSuccessNotOnAGatewayRequest() throws IOException, ServletException {
		notGatewayRequest();
		this.gatewayAwareUrlAuthenticationHandler.onAuthenticationSuccess(this.httpServletRequest, this.httpServletResponse, null);
		removedSessionAttribute();
		delegateToAuthenticationSuccessHandler();
	}

	private void delegateToAuthenticationSuccessHandler() throws IOException, ServletException {
		Mockito.verify(this.authenticationSuccessHandler, Mockito.times(1)).onAuthenticationSuccess(this.httpServletRequest, this.httpServletResponse, null);
	}

	private void removedSessionAttribute() {
		Mockito.verify(this.sessionMock, Mockito.times(1)).removeAttribute(GatewayAwareUrlAuthenticationHandler.GATEWAY_ATTEMPT);
	}

	private void delegatedToAuthenticationFailureHandler() throws IOException, ServletException {
		Mockito.verify(this.authenticationFailureHandler, Mockito.times(1)).onAuthenticationFailure(this.httpServletRequest, this.httpServletResponse, null);
	}

	private void defaultUrlFailureHandlerAfterRequestCacheCheck() throws IOException, ServletException {
		Mockito.verify(this.requestCache, Mockito.times(1)).getRequest(this.httpServletRequest, this.httpServletResponse);
		delegatedToAuthenticationFailureHandler();
	}

	public void gatewayRequest() {
		setGatewayRequest(true);
	}

	public void notGatewayRequest() {
		setGatewayRequest(false);
	}

	private void setGatewayRequest(boolean isGatewayRequest) {
		Mockito.when(this.sessionMock.getAttribute(GatewayAwareUrlAuthenticationHandler.GATEWAY_ATTEMPT)).thenReturn(isGatewayRequest);
	}

	public void defaultCachedRequest() {
		Mockito.when(this.requestCache.getRequest(this.httpServletRequest, this.httpServletResponse)).thenReturn(this.savedRequestMock);
	}

	private void notCallingTheAuthenticationFailureHandler() throws IOException, ServletException {
		Mockito.verify(this.authenticationFailureHandler, Mockito.never()).onAuthenticationFailure(this.httpServletRequest, this.httpServletResponse, null);
	}

	public void noCallToRedirectOrRequestCache() throws IOException {
		Mockito.verify(this.httpServletResponse, Mockito.never()).sendRedirect("/cached");
		Mockito.verify(this.requestCache, Mockito.never()).getRequest(this.httpServletRequest, this.httpServletResponse);
	}

	private void redirectToCachedRequest() throws IOException {
		Mockito.verify(this.redirectStrategy, Mockito.times(1)).sendRedirect(this.httpServletRequest, this.httpServletResponse, "/cached");
	}

	private void noRequestCached() {
		Mockito.when(this.requestCache.getRequest(this.httpServletRequest, this.httpServletResponse)).thenReturn(null);
	}

}
