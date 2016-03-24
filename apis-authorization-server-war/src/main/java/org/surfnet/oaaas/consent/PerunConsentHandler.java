package org.surfnet.oaaas.consent;

/**
 * @author Ondrej Velisek <ondrejvelisek@gmail.com>
 */
public class PerunConsentHandler extends FormUserConsentHandler {

  @Override
  protected String getUserConsentUrl() {
    return "/WEB-INF/jsp/perunConsent.jsp";
  }

  @Override
  protected String getUserConsentDeniedUrl() {
    return "/WEB-INF/jsp/perunConsent_denied.jsp";
  }
}
