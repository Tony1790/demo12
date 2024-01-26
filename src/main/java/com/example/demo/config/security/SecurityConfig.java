package com.example.demo.config.security;

import com.example.demo.domain.UserVo;
import com.example.demo.service.MyUserDetailsService;
import com.example.demo.utils.JwtTokenProvider;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final MyUserDetailsService myUserDetailsService;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http

                .csrf((csrfConfig) ->
                        csrfConfig.disable()
                )//1번 csrf(Cross site Request forgery) 설정을 disable 하였습니다.
                .sessionManagement((httpSecuritySessionManagementConfigurer) ->
                        httpSecuritySessionManagementConfigurer
                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )//session이 필요없기때문에 STATELESS상태로 설정하여 사용하지않는다.
                .authorizeHttpRequests((authorizeRequests)->
                        authorizeRequests
                                .requestMatchers("/", "/*/login", "/*/join").permitAll()
                                .requestMatchers("/users/**").hasRole("USER")
                                .requestMatchers("/admins/**").hasRole("ADMIN")
                                .anyRequest().hasRole("USER")
                )//3번
                .exceptionHandling((exceptionHandling)->
                        exceptionHandling.authenticationEntryPoint(new CustomAuthenticationEntryPoint()).accessDeniedHandler(new CustomAccessDeniedHandler())
                )// 401,403 예외처리
                .addFilterBefore(new JwtFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        return  http.build();
    }

}

    /*public final AuthenticationEntryPoint unauthorizedEntryPoint =
            (request, response, authException) -> {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            };

    public final AccessDeniedHandler accessDeniedHandler =
            (request, response, accessDeniedException) -> {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            };*/
/*.formLogin((formLogin) ->
                        formLogin
                                .loginPage("/login/login") //1번
                                .usernameParameter("username") //2
                                .passwordParameter("password") //3
                                .loginProcessingUrl("/login/login-proc") //4
                                .defaultSuccessUrl("/", true)//5
                )//formLogin은 로그인을 어떻게 할지 설정하는 것이다.
                .logout((logoutConfig) ->
                        logoutConfig.logoutSuccessUrl("/") //6
                )*/

        /*



                formLogin을 통해 login 설정을 할 수 있습니다.
                1. login 화면 url를 설정하였습니다.
                   기본적으로 "/login" url을 가지며 해당 url을 사용할 경우 Security에서 제공(처음에 아무 설정하지 않은 login form)하는 화면을 사용하며, 해당 옵션으로 커스텀마이징할 수 있습니다.
                2. 로그인 ID json 키 값을 설정하면 됩니다. 해당 옵션을 설정하지 않으면 "username"로 설정되고 위 사진에서는 일부러 커스텀하는 것을 보여주기 위해 설정하였습니다.
                3. 로그인 password json 키 값을 설정하면 됩니다. 설정하지 않으면 "password"로 설정됩니다.
                4. 로그인 submit 요청을 받을 URL 입니다.
                5. 로그인에 성공했을때 이동할 URL 입니다.
                6. 로그아웃에 성공했을때 이동하는 URL 입니다. 기본적으로 "/logout"입니다.
                7. submit을 통해 설정한 "/login/login-proc" 요청을 받으면 Spring Security는 요청을 받아 7번의 서비스 로직을 수행합니다.
*/
