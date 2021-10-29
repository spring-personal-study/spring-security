package io.security.basicsecurity.security.configs;

import io.security.basicsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.basicsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.basicsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.basicsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.basicsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@Order(0) // SecurityConfig 보다 먼저 설정되도록
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        final AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter();
        filter.setAuthenticationManager(authenticationManagerBean());
        filter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler());
        return filter;
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AccessDeniedHandler ajaxAccessHandler() {
        return new AjaxAccessDeniedHandler();
    }

    @Bean
    public AjaxAuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**")
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .anyRequest()
                .authenticated()
                .and()
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class); // 추가하고자 하는 필터가 기존 필터보다 앞에 두어야 할 때

        http.exceptionHandling()
                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                .accessDeniedHandler(ajaxAccessHandler());

        http.csrf().disable();

    }

}
