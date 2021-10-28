package io.security.basicsecurity.security.common;

import lombok.Getter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String secretKey;

    /**
     * 유저로부터 아이디, 비밀번호 외에 다른 정보를 더 받아와서 인증처리를 해야할 경우 사용합니다.
     * FormWebAuthenticationDetails 는 FormAuthenticationDetailsSource 에서 생성됩니다.
     * SecurityConfig 에서  FormAuthenticationDetailsSource 를 가져와 설정해야 합니다.
     * 그러면 유저가 보낸 추가값을 CustomAuthenticationProvider 에서 실제 검증을 하는데 사용할 수 있습니다.
     *
     * @param request that the authentication request was received from user
     */
    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretKey = request.getParameter("secret_key");
    }


}
