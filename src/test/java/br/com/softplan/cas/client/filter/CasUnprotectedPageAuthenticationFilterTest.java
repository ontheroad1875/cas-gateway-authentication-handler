package br.com.softplan.cas.client.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.RequestCache;

import br.com.softplan.cas.client.authentication.GatewayAwareUrlAuthenticationHandler;

public class CasUnprotectedPageAuthenticationFilterTest {

	private Authentication authentication;

	private CasUnprotectedPageAuthenticationFilter casUnprotectedPageAuthenticationFilter;

	private CasAuthenticationEntryPoint casAuthenticationEntryPoint;

	private HttpServletRequest httpServletRequest;

	private HttpServletResponse httpServletResponse;

	private HttpSession sessionMock;

	private FilterChain filterChain;

	private RequestCache requestCacheMock;

	private Cookie[] cookiesWithoutAuthenticationCookie = new Cookie[] { new Cookie("RANDOM_COOKIE_1", "AAAA"), new Cookie("WHATEVER", "XXXXX") };

	private Cookie[] cookiesWithAuthenticationCookie = new Cookie[] { new Cookie("TGC", "TICKET_BLABLA"), new Cookie("WHATEVER", "XXXXX") };

	private SecurityContext securityContextMock;

	@Before
	public void initializeTests() throws Exception {
		// Initialize the SecurityContextHolder
		this.authentication = Mockito.mock(Authentication.class);
		this.securityContextMock = Mockito.mock(SecurityContext.class);
		SecurityContextHolder.setContext(this.securityContextMock);
		// Mocked authenticationEntryPoint
		this.casAuthenticationEntryPoint = Mockito.mock(CasAuthenticationEntryPoint.class);
		this.requestCacheMock = Mockito.mock(RequestCache.class);
		this.casUnprotectedPageAuthenticationFilter = new CasUnprotectedPageAuthenticationFilter(this.casAuthenticationEntryPoint, "TGC", this.requestCacheMock);
		this.casUnprotectedPageAuthenticationFilter.afterPropertiesSet();
		// Mocked request and response
		this.sessionMock = Mockito.mock(HttpSession.class);
		this.httpServletRequest = Mockito.mock(HttpServletRequest.class);
		Mockito.when(this.httpServletRequest.getSession()).thenReturn(this.sessionMock);
		this.httpServletResponse = Mockito.mock(HttpServletResponse.class);
		// Chain
		this.filterChain = Mockito.mock(FilterChain.class);
	}

	/**
	 * User with cookies is not logged on cas. So it shouldn't try to authenticate on cas.
	 *
	 * @throws ServletException
	 * @throws IOException
	 */
	@Test
	public void userIsNotLoggedOnCas() throws IOException, ServletException {
		userIsNotLoggedIn(this.cookiesWithoutAuthenticationCookie);
		this.casUnprotectedPageAuthenticationFilter.doFilter(this.httpServletRequest, this.httpServletResponse, this.filterChain);
		userDidntTriedToAuthenticate();
	}

	/**
	 * User with cookies is not logged on cas. So it shouldn't try to authenticate on cas.
	 *
	 * @throws ServletException
	 * @throws IOException
	 */
	@Test
	public void userIsNotLoggedOnCasWithoutCookies() throws IOException, ServletException {
		userIsNotLoggedIn();
		this.casUnprotectedPageAuthenticationFilter.doFilter(this.httpServletRequest, this.httpServletResponse, this.filterChain);
		userDidntTriedToAuthenticate();
	}

	/**
	 * User without cookies is not logged on cas. So it shouldn't try to authenticate on cas.
	 *
	 * @throws ServletException
	 * @throws IOException
	 */
	@Test
	public void userIsLoggedOnCasButNotOnTheApplication() throws IOException, ServletException {
		userIsNotLoggedIn(this.cookiesWithAuthenticationCookie);
		this.casUnprotectedPageAuthenticationFilter.doFilter(this.httpServletRequest, this.httpServletResponse, this.filterChain);
		userTriedToInitiateAuthentication();
		gatewayAttemptSet();
	}

	@Test
	public void userIsAlreadyLoggedOnTheApplication() throws IOException, ServletException {
		userIsLoggedIn();
		this.casUnprotectedPageAuthenticationFilter.doFilter(this.httpServletRequest, this.httpServletResponse, this.filterChain);
		userDidntTriedToAuthenticate();
	}

	private void userIsNotLoggedIn(Cookie... cookies) {
		Mockito.when(this.securityContextMock.getAuthentication()).thenReturn(Mockito.mock(AnonymousAuthenticationToken.class));
		Mockito.when(this.httpServletRequest.getCookies()).thenReturn(cookies);
	}

	private void userIsLoggedIn() {
		Mockito.when(this.securityContextMock.getAuthentication()).thenReturn(this.authentication);
	}

	private void userDidntTriedToAuthenticate() throws IOException, ServletException {
		Mockito.verify(this.casAuthenticationEntryPoint, Mockito.never()).commence(this.httpServletRequest, this.httpServletResponse, null);
	}

	private void userTriedToInitiateAuthentication() throws IOException, ServletException {
		Mockito.verify(this.casAuthenticationEntryPoint, Mockito.times(1)).commence(this.httpServletRequest, this.httpServletResponse, null);
	}

	private void gatewayAttemptSet() {
		Mockito.verify(this.sessionMock, Mockito.times(1)).setAttribute(GatewayAwareUrlAuthenticationHandler.GATEWAY_ATTEMPT, true);
	}

}
