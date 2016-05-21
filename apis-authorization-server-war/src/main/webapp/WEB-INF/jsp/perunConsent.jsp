<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="description" content="" />
  <meta name="author" content="" />
  <title>Consent</title>
  <!-- Latest compiled and minified CSS -->
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">
  <!-- Le styles -->
  <link rel="stylesheet" href="${pageContext.request.contextPath}/client/css/perun-style.css" />

  <!-- Le HTML5 shim, for IE6-8 support of HTML5 elements -->
  <!--[if lt IE 9]>
  <script src="http://html5shim.googlecode.com/svn/trunk/html5.js"></script>
  <![endif]-->
</head>
<body>


<div class="main">

  <div class="container">
    <div class="row">
      <div class="col-sm-8 col-sm-offset-2 col-md-6 col-md-offset-3">

        <div class="page-header">
          <h1><strong>${client.name}</strong>
            asks for permission to access service
            <strong>${client.resourceServer.name}</strong></h1>
        </div>

        <div class="consent">
          <img alt="${client.name}" title="${client.name}" src="${client.thumbNailUrl}" />
          <img class="arrow" src="${pageContext.request.contextPath}/client/img/arrow.png" />
          <img alt="${client.resourceServer.name}"
            title="${client.resourceServer.name}"
            src="${client.resourceServer.thumbNailUrl}" />
        </div>

        <form id="accept" method="post" action="${pageContext.request.contextPath}${actionUri}">
          <input type="hidden" name="AUTH_STATE" value="${AUTH_STATE}"/>

          <c:if test="${not empty client.scopes}">

            <h2>This data will be shared</h2>

            <fieldset>
              <c:forEach items="${client.scopes}" var="availableScope">
                <c:set var="checked" value="" />
                <c:forEach var="requestedScope" items="${requestedScopes}">
                  <c:if test="${requestedScope eq availableScope}">
                    <c:set var="checked" value="CHECKED" />
                  </c:if>
                </c:forEach>
                <input type="checkbox" id="GRANTED_SCOPES" name="GRANTED_SCOPES" <c:out value="${checked}"/>
                       value="${availableScope}"/>
                <span class="consent-label">${availableScope}</span><br/>
              </c:forEach>
            </fieldset>

          </c:if>

          <fieldset>
            <div class="form-actions">
              <button id="user_oauth_approval" name="user_oauth_approval" value="true" type="submit"
                      class="btn btn-success btn-lg btn-block">Grant permission</button>
              <div class="or">or</div>
              <button type="submit" name="user_oauth_approval" value="false"
                      class="btn btn-danger btn-lg btn-block">Deny permission</button>
            </div>
          </fieldset>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="foot">
  <p>Powered by <a href="http://www.surfnet.nl/">SURFnet</a>. Fork me on <a href="https://github.com/OpenConextApps/oa-aas/">Github</a>. Licensed under the <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License 2.0</a>.</p>
</div>

</body>
</html>
