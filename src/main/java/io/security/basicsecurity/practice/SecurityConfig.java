//package io.security.basicsecurity;
//
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
//import org.springframework.security.web.savedrequest.RequestCache;
//import org.springframework.security.web.savedrequest.SavedRequest;
//
//import javax.servlet.http.HttpSession;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Set;
//import java.util.stream.Collectors;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//    // @Bean public PasswordEncoder getPasswordEncoder() { return new BCryptPasswordEncoder(); }
//
//    //@Bean public InMemoryUserDetailsManager inMemoryUserDetailsManager() { return new InMemoryUserDetailsManager(); }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
//        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS");
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}4321").roles("ADMIN");
//       // auth.userDetailsService(inMemoryUserDetailsManager());
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//
//        // 인가 관리 (인증된 유저에 대하여, 어디까지 접근이 가능한지를 설정)
//        http.authorizeRequests()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("SYS")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
//                .anyRequest().authenticated();
//
//        // form 로그인
//        http.formLogin()
//                //.defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler((request, response, authentication) -> {
//                    System.out.println("authentication: " + authentication.getName());
//                    RequestCache cache = new HttpSessionRequestCache();
//                    SavedRequest savedRequest = cache.getRequest(request, response);
//                    if (savedRequest != null) {
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        response.sendRedirect(redirectUrl);
//                    }
//                }) // 인증이 성공했다면 유저가 가고자 했던 url로 이동할 수 있게 함.
//                // 인증 또는 인가 실패시 인증/인가 예외처리가 됨 (아래에 예외처리 설정이 있다.)
//
//                .failureHandler((request, response, exception) -> {
//                    System.out.println("exception: " + exception.getMessage());
//                  //  System.out.println("inMemoryConfiguration.loadUserByUsername(\"user1\").getPassword(): " + inMemoryUserDetailsManager.userExists("user1"));
//                    response.sendRedirect("/login");
//                })
//                .permitAll();
//
//        // 로그아웃 설정
//        http.logout()
//                .logoutUrl("/logout")
//                .addLogoutHandler((request, response, authentication) -> {
//                    HttpSession session = request.getSession();
//                    session.invalidate();
//                })
//                .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/login"))
//                .deleteCookies("remember-me");
//
//        // 리멤버미 (유저 정보 기억) 활성화
//        UserDetailsService userDetailsService = new UserDetailsService();
//        http.rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
//
//        // 세션 관리 활성화
//        http.sessionManagement()
//                .sessionFixation().changeSessionId()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true)
//                .expiredUrl("/expired");
//
//        /*
//        // 인증/인증 예외처리 활성화.
//        http.exceptionHandling()
//                .authenticationEntryPoint(((request, response, authException) -> {
//                    System.out.println("인증 실패");
//                    response.sendRedirect("/login");
//                })) //인증 예외 처리 인터페이스
//                .accessDeniedHandler(((request, response, accessDeniedException) -> {
//                    System.out.println("인가 실패");
//                    response.sendRedirect("/denied");
//                })); // 인가 예외 처리 인터페이스
//         */
//    }
//}
//
//class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        /*
//            final String ip = request.getRemoteAddr();
//            if (loginAttemptService.isBlocked(ip)) {
//                throw new RuntimeException("blocked");
//            }
//        */
//        UserRepository userRepository = new UserRepository();
//
//        Account account = userRepository.findByUsername(username);
//        if (account == null) {
//            if (userRepository.countByUsername(username) == 0) {
//                throw new UsernameNotFoundException("No user found with username: " + username);
//            }
//        }
//        Set<String> userRoles = account.userRole
//                .stream()
//                .map(Account.UserRole::getRoleName)
//                .collect(Collectors.toSet());
//
//        return new UserDetail(account, new ArrayList<>(userRoles));
//    }
//}
//
//class UserDetail extends org.springframework.security.core.userdetails.User {
//
//    public UserDetail(Account account, List<String> roles) {
//        super(account.username, account.password, roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
//
//    }
//}
//
//class Account {
//    public final String username;
//    public final String password;
//    public final List<UserRole> userRole = new ArrayList<>();
//
//    public Account(String username, String password, UserRole userRole) {
//        this.username = username;
//        this.password = password;
//        this.userRole.add(userRole);
//    }
//
//    enum UserRole {
//        USER("유저"), MANAGER("관리자");
//        private final String roleName;
//
//        UserRole(String roleName) {
//            this.roleName = roleName;
//        }
//
//        public String getRoleName() {
//            return roleName;
//        }
//    }
//}
//
//class UserRepository {
//    public Account findByUsername(String username) {
//        return new Account("charlie", "1234", Account.UserRole.USER);
//    }
//
//    public int countByUsername(String username) {
//        return 1;
//    }
//}