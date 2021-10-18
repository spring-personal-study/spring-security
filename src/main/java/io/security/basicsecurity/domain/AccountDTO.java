package io.security.basicsecurity.domain;


import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter @ToString @Setter
public class AccountDTO {
    private Long id;
    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
