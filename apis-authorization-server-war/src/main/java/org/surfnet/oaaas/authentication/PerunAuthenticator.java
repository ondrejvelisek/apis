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

import org.apache.commons.lang.StringUtils;
import org.apache.openjpa.util.UnsupportedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link AbstractAuthenticator} that expect the user is already (and MUST be) authenticated by another component
 * infront of authorization server (e.g. Apache Web server) and get all neccessary parametres in request.
 */
@Named("perunAuthenticator")
public class PerunAuthenticator extends AbstractAuthenticator {

  private final static Logger log = LoggerFactory.getLogger(PerunAuthenticator.class);

  @Override
  public boolean canCommence(HttpServletRequest request) {
    return getAuthStateValue(request) != null;
  }

  @Override
  public void authenticate(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      String authStateValue, String returnUri) throws IOException, ServletException {
    setAuthStateValue(request, authStateValue);
    AuthenticatedPrincipal principal = setupPrincipal(request);
    if (true) {
      throw new IllegalStateException("ext source login: "+principal.getName()+"   \n   "+principal.getAttributes());
    }
    setPrincipal(request, principal);
    chain.doFilter(request, response);
  }

  private AuthenticatedPrincipal setupPrincipal(HttpServletRequest req) {
    String extSourceLoaString = null;
    String extLogin = null;
    String extSourceName = null;
    String extSourceType = null;
    int extSourceLoa = 0;
    Map<String, String> additionalInformations = new HashMap<String, String>();

    // If we have header Shib-Identity-Provider, then the user uses identity federation to authenticate
    if (req.getHeader("Shib-Identity-Provider") != null && !req.getHeader("Shib-Identity-Provider").isEmpty()) {
      extSourceName = (String) req.getHeader("Shib-Identity-Provider");
      extSourceType = ExtSourcesManager.EXTSOURCE_IDP;
      if (req.getHeader("loa") != null && ! req.getHeader("loa").isEmpty()) {
        extSourceLoaString = req.getHeader("loa");
      } else {
        extSourceLoaString = "2";
      }
      // FIXME: find better place where do the operation with attributes from federation
      if (req.getHeader("eppn") != null && ! req.getHeader("eppn").isEmpty()) {
        try {
          String eppn = new String(req.getHeader("eppn").getBytes("ISO-8859-1"));

          // Remove scope from the eppn attribute
          additionalInformations.put("eppnwoscope", eppn.replaceAll("(.*)@.*", "$1"));
        } catch (UnsupportedEncodingException e) {
          log.error("Cannot encode header eppn with value from ISO-8859-1.");
        }
      }
      if (req.getRemoteUser() != null && !req.getRemoteUser().isEmpty()) {
        extLogin = req.getRemoteUser();
      }
    }

    // EXT_SOURCE was defined in Apache configuration (e.g. Kerberos or Local)
    else if (req.getAttribute("EXTSOURCE") != null) {
      extSourceName = (String) req.getAttribute("EXTSOURCE");
      extSourceType = (String) req.getAttribute("EXTSOURCETYPE");
      extSourceLoaString = (String) req.getAttribute("EXTSOURCELOA");

      if (req.getRemoteUser() != null && !req.getRemoteUser().isEmpty()) {
        extLogin = req.getRemoteUser();
      } else if (req.getAttribute("ENV_REMOTE_USER") != null && !((String) req.getAttribute("ENV_REMOTE_USER")).isEmpty()) {
        extLogin = (String) req.getAttribute("ENV_REMOTE_USER");
      } else if (extSourceName.equals(ExtSourcesManager.EXTSOURCE_NAME_LOCAL)) {
        /** LOCAL EXTSOURCE **/
        // If ExtSource is LOCAL then generate REMOTE_USER name on the fly
        extLogin = Long.toString(System.currentTimeMillis());
      }
    }

    // X509 cert was used
    // Cert must be last since Apache asks for certificate everytime and fills cert properties even when Kerberos is in place.
    else if (extLogin == null && req.getAttribute("SSL_CLIENT_VERIFY") != null && ((String) req.getAttribute("SSL_CLIENT_VERIFY")).equals("SUCCESS")){
      extSourceName = (String) req.getAttribute("SSL_CLIENT_I_DN");
      extSourceType = ExtSourcesManager.EXTSOURCE_X509;
      extSourceLoaString = (String) req.getAttribute("EXTSOURCELOA");
      extLogin = (String) req.getAttribute("SSL_CLIENT_S_DN");

      // Store X509
      additionalInformations.put("SSL_CLIENT_S_DN", (String) req.getAttribute("SSL_CLIENT_S_DN"));
      additionalInformations.put("dn", (String) req.getAttribute("SSL_CLIENT_S_DN"));

      // Get the X.509 certificate object
      X509Certificate[] certs = (X509Certificate[]) req.getAttribute("javax.servlet.request.X509Certificate");

      // Get the emails
      if (certs != null && certs.length > 0 && certs[0] != null) {
        String emails = "";

        Collection<List<?>> altNames;
        try {
          altNames = certs[0].getSubjectAlternativeNames();
          if (altNames != null) {
            for (List<?> entry: altNames) {
              if (((Integer) entry.get(0)) == 1) {
                emails = (String) entry.get(1);
              }
            }
          }
        } catch (CertificateParsingException e) {
          log.error("Error during parsing certificate {}", certs);
        }

        additionalInformations.put("mail", emails);

        // Get organization from the certificate
        String oRegExpPattern = "(o|O)(\\s)*=([^+,])*";
        Pattern oPattern = Pattern.compile(oRegExpPattern);
        Matcher oMatcher = oPattern.matcher(certs[0].getSubjectX500Principal().getName());
        if (oMatcher.find()) {
          String[] org = oMatcher.group().split("=");
          if (org[1] != null && !org[1].isEmpty()) {
            additionalInformations.put("o", org[1]);
          }
        }
      }
    }

    // Read all headers and store them in additionalInformation
    String headerName = "";
    for(Enumeration<String> headerNames = req.getHeaderNames(); headerNames.hasMoreElements();){
      headerName = (String)headerNames.nextElement();
      // Tomcat expects all headers are in ISO-8859-1
      try {
        additionalInformations.put(headerName, new String(req.getHeader(headerName).getBytes("ISO-8859-1")));
      } catch (UnsupportedEncodingException e) {
        log.error("Cannot encode header {} with value from ISO-8859-1.", headerName, req.getHeader(headerName));
      }
    }

    // extSourceLoa must be number, if any specified then set to 0
    if (extSourceLoaString == null || extSourceLoaString.isEmpty()) {
      extSourceLoa = 0;
    } else {
      try {
        extSourceLoa = Integer.parseInt(extSourceLoaString);
      } catch (NumberFormatException ex) {
        extSourceLoa = 0;
      }
    }

    AuthenticatedPrincipal principal = new AuthenticatedPrincipal(extLogin);

    additionalInformations.put("extSourceName", extSourceName);
    additionalInformations.put("extSourceType", extSourceType);
    additionalInformations.put("extSourceLoa", String.valueOf(extSourceLoa));
    principal.setAttributes(additionalInformations);

    return principal;
  }



}
