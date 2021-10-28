package io.security.basicsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final RequestCache cache = new HttpSessionRequestCache();
    private final RedirectStrategy strategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");

        SavedRequest savedRequest = cache.getRequest(request, response);
        // 사용자가 인증이 필요한 url 에 접근을 했는데 인증되지 않아서, 인증을 하면 원래 가고자 했던 url 로 바로 이동할 수 있게끔 설정한다.
        if (savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl();
            strategy.sendRedirect(request, response, targetUrl); // 인증
        } else {
            strategy.sendRedirect(request, response, getDefaultTargetUrl());
        }
    }
}
