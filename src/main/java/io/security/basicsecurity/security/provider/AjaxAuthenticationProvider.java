package io.security.basicsecurity.security.provider;

import io.security.basicsecurity.security.common.FormWebAuthenticationDetails;
import io.security.basicsecurity.security.service.AccountContext;
import io.security.basicsecurity.security.token.AjaxAuthenticationToken;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.apache.naming.factory.BeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@NoArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * https://reminiscent-headlight-ee3.notion.site/Authentication-Flow-8f5a6645df684394a60ba28a4c6d7236
     *
     * @param authentication 사용자가 입력한 인증 정보가 담겨있는 파라매터. getName: 아이디, getCredential: 비밀번호.
     *                       <br> UsernamePasswordAuthenticationFilter 가 이 타입의 (id + password 를 담은)클래스를 생성 후
     *                       <br> AuthenticationManager 에게 전달한다.
     *                       <br> AuthenticationManager 는 AuthenticationProvider 가 authenticate() 를 수행하도록 위임하는데,
     *                       <br> AuthenticationProvider 는 authenticate() 를 실행하는 도중
     *                       <br> 인증에 필요한 정보들을 UserDetailsService 에서 꺼내와 비교한다.
     * @return 인증처리 결과값 (데이터베이스에 저장된--즉 CustomUserDetailsService 의 loadUserByUsername 에서 꺼내온--
     * <br> 데이터와 유저가 입력한 값이 일치한지 검증한 결과)
     * @throws AuthenticationException 인증처리 실패
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        AccountContext userDetails = (AccountContext) userDetailsService.loadUserByUsername(authentication.getName());
        String password = (String) authentication.getCredentials();

        // 이미 저장되어 있는 암호와 유저가 인증을 시도했을때 작성한 비밀번호가 맞는지 검사하여 일치하지 않으면 인증실패가 되도록 처리
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new BadCredentialsException("인증 실패. 비밀번호가 다릅니다.");
        }

        // secret_key 추가 검증
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        FormWebAuthenticationDetails secret = (FormWebAuthenticationDetails) details;
        // 시큐리티설정에서
        // .authenticationDetailsSource(authenticationDetailsSource)
        // 를 설정하지 않으면 캐스팅 못함
        if (secret.getSecretKey() == null || !secret.getSecretKey().equals("secret")) {
            throw new InsufficientAuthenticationException("인증하는데 필요한 정보가 불충분합니다.");
        }

        return new AjaxAuthenticationToken(userDetails.getAccount(), null, userDetails.getAuthorities());
    }

    /**
     * @param authentication 이 파라매터와 AjaxAuthenticationProvider 가 사용하고자 하는 토큰의 타입이 일치할 때 Provider 가 인증처리를 할 수 있도록 설정
     * @return 인증 처리 가능 여부
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(AjaxAuthenticationToken.class);
    }
}
