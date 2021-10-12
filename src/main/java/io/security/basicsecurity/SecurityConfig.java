package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated();
        http.formLogin()
                //.loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication: " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception: " + exception.getMessage());
                        response.sendRedirect("/loginPage");
                    }
                })
                .permitAll();

        http.logout()
                .logoutUrl("/logout")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");

        UserDetailsService userDetailsService = new UserDetailsService();
        http.rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);
    }
}

class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        /*
            final String ip = request.getRemoteAddr();
            if (loginAttemptService.isBlocked(ip)) {
                throw new RuntimeException("blocked");
            }
        */
        UserRepository userRepository = new UserRepository();

        Account account = userRepository.findByUsername(username);
        if (account == null) {
            if (userRepository.countByUsername(username) == 0) {
                throw new UsernameNotFoundException("No user found with username: " + username);
            }
        }
        Set<String> userRoles = account.userRole
                .stream()
                .map(Account.UserRole::getRoleName)
                .collect(Collectors.toSet());

        return new UserDetail(account, new ArrayList<>(userRoles));
    }
}

class UserDetail extends org.springframework.security.core.userdetails.User {

    public UserDetail(Account account, List<String> roles) {
        super(account.username, account.password, roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

    }
}

class Account {
    public final String username;
    public final String password;
    public final List<UserRole> userRole = new ArrayList<>();

    public Account(String username, String password, UserRole userRole) {
        this.username = username;
        this.password = password;
        this.userRole.add(userRole);
    }

    enum UserRole {
        USER("유저"), MANAGER("관리자");
        private final String roleName;

        UserRole(String roleName) {
            this.roleName = roleName;
        }

        public String getRoleName() {
            return roleName;
        }
    }
}

class UserRepository {
    public Account findByUsername(String username) {
        return new Account("charlie", "1234", Account.UserRole.USER);
    }

    public int countByUsername(String username) {
        return 1;
    }
}