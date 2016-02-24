/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.surfnet.oaaas.authentication;

import org.surfnet.oaaas.auth.AbstractAuthenticator;
import org.surfnet.oaaas.auth.principal.AuthenticatedPrincipal;

import javax.inject.Named;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * {@link AbstractAuthenticator} that expect the user is already (and MUST be) authenticated by another component
 * infront of authorization server (e.g. Apache Web server) and get all neccessary parametres in request.
 */
@Named("perunAuthenticator")
public class PerunAuthenticator extends AbstractAuthenticator {

  private static final String SESSION_IDENTIFIER = "AUTHENTICATED_PRINCIPAL";

  @Override
  public boolean canCommence(HttpServletRequest request) {
    return getAuthStateValue(request) != null;
  }

  @Override
  public void authenticate(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      String authStateValue, String returnUri) throws IOException, ServletException {
    HttpSession session = request.getSession(false);
    setAuthStateValue(request, authStateValue);
    AuthenticatedPrincipal principal = (AuthenticatedPrincipal) (session != null ? session
        .getAttribute(SESSION_IDENTIFIER) : null);
    if (principal != null) {
      // we stil have the session
      setPrincipal(request, principal);
      chain.doFilter(request, response);
    } else {
      processInitial(request, response, returnUri, authStateValue);
      chain.doFilter(request, response);
    }
  }

  private void processInitial(HttpServletRequest request, ServletResponse response, String returnUri,
                              String authStateValue) throws IOException, ServletException {

    String username;
    username = request.getRemoteUser();
    if (username == null) {
      username = (String) request.getAttribute("ENV_REMOTE_USER");
    }
    if (username == null) {
      username = request.getHeader("ENV_REMOTE_USER");
    }

    AuthenticatedPrincipal principal = new AuthenticatedPrincipal(username);

    principal.setAdminPrincipal(true);

    // TODO - parse attributes from request and put it into principal

    request.getSession().setAttribute(SESSION_IDENTIFIER, principal);
    setPrincipal(request, principal);
  }

}
