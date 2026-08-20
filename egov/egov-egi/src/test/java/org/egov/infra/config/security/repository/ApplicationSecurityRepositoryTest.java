package org.egov.infra.config.security.repository;

import static org.egov.infra.utils.ApplicationConstant.MS_TENANTID_KEY;
import static org.egov.infra.utils.ApplicationConstant.MS_USER_TOKEN;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.egov.infra.admin.master.entity.CustomUserDetails;
import org.egov.infra.admin.master.entity.User;
import org.egov.infra.config.security.authentication.userdetail.CurrentUser;
import org.egov.infra.microservice.contract.UserSearchResponse;
import org.egov.infra.microservice.contract.UserSearchResponseContent;
import org.egov.infra.microservice.utils.MicroserviceUtils;
import org.egov.infra.persistence.entity.enums.UserType;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.HttpRequestResponseHolder;

/**
 * Exercises the two fixes for the premature "Session Expired" / "AuthToken not found"
 * bug: the Redis TTL must slide forward on every request that resolves a user (instead
 * of expiring on an absolute clock from the last login), and getUserDetails() must fall
 * back to the token/tenant already stashed on the HttpSession when a request (e.g. a
 * background AJAX call) doesn't carry auth_token/tenantId as URL parameters.
 */
public class ApplicationSecurityRepositoryTest {

    private static final String SESSION_ID = "test-session-id";

    private ApplicationSecurityRepository repository;
    private MicroserviceUtils microserviceUtils;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpSession session;

    @Before
    public void before() {
        repository = new ApplicationSecurityRepository();
        microserviceUtils = mock(MicroserviceUtils.class);
        repository.microserviceUtils = microserviceUtils;

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(SESSION_ID);
        when(request.getRequestURL())
                .thenReturn(new StringBuffer("http://localhost/services/EGF/common/getschemesbyfundid"));
    }

    @Test
    public void shouldRenewRedisTtlOnEverySuccessfulRequest() {
        User user = new User(UserType.EMPLOYEE);
        user.setPwdExpiryDate(new Date(System.currentTimeMillis() + 100000));
        CurrentUser cachedUser = new CurrentUser(user);

        when(request.getParameter("auth_token")).thenReturn(null);
        when(request.getParameter("tenantId")).thenReturn(null);
        when(microserviceUtils.readFromRedis(SESSION_ID, "current_user")).thenReturn(cachedUser);

        SecurityContext context = repository.loadContext(new HttpRequestResponseHolder(request, response));

        assertNotNull("expected an authenticated context when the user is already cached in redis",
                context.getAuthentication());
        verify(microserviceUtils, times(1)).setExpire(SESSION_ID);
    }

    @Test
    public void shouldFallBackToSessionTokenWhenAuthTokenParamMissing() {
        // Simulate an AJAX call (e.g. getschemesbyfundid) that carries no auth_token/tenantId
        // URL params, but a valid token/tenant already stashed on the HttpSession from login.
        when(request.getParameter("auth_token")).thenReturn(null);
        when(request.getParameter("tenantId")).thenReturn(null);
        when(session.getAttribute(MS_USER_TOKEN)).thenReturn("stashed-user-token");
        when(session.getAttribute(MS_TENANTID_KEY)).thenReturn("ch");

        // Nothing cached in redis, forcing loadContext() into getUserDetails().
        when(microserviceUtils.readFromRedis(SESSION_ID, "current_user")).thenReturn(null);
        when(microserviceUtils.generateAdminToken("ch")).thenReturn("admin-token");

        CustomUserDetails validated = new CustomUserDetails();
        validated.setId(42L);
        validated.setTenantId("ch");
        validated.setUserName("jdoe");
        when(microserviceUtils.getUserDetails("stashed-user-token", "admin-token")).thenReturn(validated);

        UserSearchResponseContent content = new UserSearchResponseContent();
        content.setId(42L);
        content.setUserName("jdoe");
        content.setName("Jane Doe");
        content.setType("EMPLOYEE");
        content.setActive(true);
        content.setAccountLocked(false);
        content.setLocale("en_IN");
        content.setUuid("uuid-42");
        content.setPwdExpiryDate(new Date(System.currentTimeMillis() + 100000));
        content.setRoles(new ArrayList<>());

        UserSearchResponse userSearchResponse = new UserSearchResponse();
        userSearchResponse.setUserSearchResponseContent(Collections.singletonList(content));
        when(microserviceUtils.getUserInfo("stashed-user-token", "ch", "jdoe")).thenReturn(userSearchResponse);

        SecurityContext context = repository.loadContext(new HttpRequestResponseHolder(request, response));

        // Proves the "AuthToken not found" branch was never hit: the request succeeded
        // using the token/tenant recovered from the HttpSession, not the (absent) URL params.
        assertNotNull("expected the fallback token to authenticate the request successfully",
                context.getAuthentication());
        verify(microserviceUtils).generateAdminToken("ch");
        verify(microserviceUtils).savetoRedis(eq(SESSION_ID), eq("current_user"), anyObject());
    }
}
