package io.security.basicsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.basicsecurity.domain.AccountDTO;
import io.security.basicsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.ObjectUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if (!isAjax(request)) {
            throw new IllegalStateException("This Authentication is not supported.");
        }

        AccountDTO accountDTO = objectMapper.readValue(request.getReader(), AccountDTO.class);

        if (ObjectUtils.isEmpty(accountDTO.getUsername()) || ObjectUtils.isEmpty(accountDTO.getPassword())) {
            throw new IllegalArgumentException("Username or Password is Empty.");
        }
        AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDTO.getUsername(), accountDTO.getPassword());

        return getAuthenticationManager().authenticate(token);
    }

    private boolean isAjax(HttpServletRequest request) {
        return request.getHeader("X-Requested-With").equals("XMLHttpRequest");
    }
}
