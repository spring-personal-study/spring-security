package io.security.basicsecurity.security.service;

import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userDetailsService")
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username)
                                        .orElseThrow(() -> new UsernameNotFoundException("유저이름으로 유저를 찾을 수 없습니다."));
        return new AccountContext(account, List.of(new SimpleGrantedAuthority(account.getRole())));
    }
}
