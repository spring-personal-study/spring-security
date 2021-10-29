package io.security.basicsecurity.security.token;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    //인증을 받기 전 사용자의 인증 정보를 담는데 사용
    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    //인증에 성공한 이후 사용자의 인증 정보를 담는데 사용
    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (isAuthenticated()) {
            throw new IllegalArgumentException("Cannot set this token to trusted = use constructor which takes a GrantedAuthority list instead");
        }
        super.setAuthenticated(authenticated);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }
}
