package cz.metacentrum.perun.oauth;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpMethod;
import org.surfnet.oaaas.auth.AbstractAuthenticator;
import org.surfnet.oaaas.auth.principal.AuthenticatedPrincipal;
import org.surfnet.oaaas.consent.FormUserConsentHandler;
import org.surfnet.oaaas.model.AccessToken;
import org.surfnet.oaaas.model.AuthorizationRequest;
import org.surfnet.oaaas.model.Client;
import org.surfnet.oaaas.repository.AccessTokenRepository;
import org.surfnet.oaaas.repository.AuthorizationRequestRepository;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.List;

/**
 * @author Ondrej Velisek <ondrejvelisek@gmail.com>
 */
public class PerunConsentHandler extends FormUserConsentHandler {

  @Inject
  private AuthorizationRequestRepository authorizationRequestRepository;

  @Override
  protected boolean processForm(final HttpServletRequest request, final HttpServletResponse response)
    throws ServletException, IOException {
    if (Boolean.valueOf(request.getParameter(USER_OAUTH_APPROVAL))) {
      setAuthStateValue(request, request.getParameter(AUTH_STATE));
      String[] scopes = request.getParameterValues(GRANTED_SCOPES);
      setGrantedScopes(request, scopes);
      return true;
    } else {
      response.sendRedirect(getUserConsentDeniedUrl(request.getParameter(AUTH_STATE)));
      return false;
    }
  }



  @Override
  protected String getUserConsentUrl() {
    return "/WEB-INF/jsp/perunConsent.jsp";
  }

  protected String getUserConsentDeniedUrl(String authState) {
    AuthorizationRequest authorizationRequest = authorizationRequestRepository.findByAuthState(authState);
    URI redirectUri = UriBuilder.fromUri(authorizationRequest.getRedirectUri())
      .queryParam("error", "access_denied")
      .queryParam("state", authorizationRequest.getAuthState())
      .build();
    return redirectUri.toString();
  }
}
