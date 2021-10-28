package io.security.basicsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMsg = "invalid username or password";

        if (exception instanceof BadCredentialsException) {
            errorMsg = "invalid username or password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMsg = "invalid secret key";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMsg);
        super.onAuthenticationFailure(request, response, exception);
    }
}
