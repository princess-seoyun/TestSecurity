package com.example.securityback.config;


import com.example.securityback.jwt.JWTFilter;
import com.example.securityback.jwt.JWTUtil;
import com.example.securityback.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.tomcat.Jar;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity // Spring Security를 사용하는 웹 보안을 활성화
public class SecurityConfig {

    // AuthenticationManager 가 인자로 받을 AuthenticationConfiguration 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    // AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManger(AuthenticationConfiguration configuration) throws Exception{

        return configuration.getAuthenticationManager();
    }

    // Spring Security에서 제공하는 비밀번호 인코딩을 위한 클래스
    // 사용자의 비밀번호를 안전하게 해싱(hash)하기 위해 사용되는 클래스
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    // Spring Security에서 요청에 대한 보안 필터 체인을 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // CORS 설정 시큐리티쪽 설정
        http
                .cors((cors) -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                                CorsConfiguration configuration = new CorsConfiguration();

                                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000")); // 3000 번대 포트를 허용한다는 것
                                configuration.setAllowedMethods(Collections.singletonList("*")); // 모든 메소드 허용
                                configuration.setAllowCredentials(true);
                                configuration.setAllowedHeaders(Collections.singletonList("*"));
                                configuration.setMaxAge(3600L);

                                configuration.setExposedHeaders(Collections.singletonList("Authorization")); // JWT 를 Authorization 를 넣어서 반환할 것이기 때문에 이것도 허용한다는 걸 추가


                                return configuration;
                            }
                        }));

        // csrf disable
        http
                .csrf((auth) -> auth.disable()); // CSRF(Cross-Site Request Forgery) 보호 기능을 비활성화, CSRF 공격으로부터 보호받기 위함

        // Form 로그인 방식 disable
        http
                .httpBasic((auth) -> auth.disable()); // HTTP 기본 인증 방식을 비활성화

        // 경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll() // 로그인, 루트 경로, 회원가입 경로는 모든 사용자에게 허용
                        .requestMatchers("/admin").hasRole("ADMIN") // "/admin" 경로는 ADMIN 권한을 가진 사용자에게만 허용
                        .anyRequest().authenticated()); // 그 외의 모든 요청은 인증된 사용자만 접근가능

        // 시큐리티가 동작할 때 JWTFilter 할 수 있도록
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 필터 등록, at이 붙은 이유는 그 자리에 등록한다는 것
        // 로그인 필터를 등록하고, 그 위치를 어디로 할 것인지 2개 인자를 넣음
        http
                .addFilterAt(new LoginFilter(authenticationManger(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)); // 세션 생성 정책을 STATELESS로 설정하여 세션을 사용하지 않도록 함, RESTful API와 같이 상태를 유지하지 않는 서비스에서 사용

        return http.build();

        // ** 결론 **
        // 이렇게 설정된 Spring Security 구성은 CSRF 및 HTTP 기본 인증을 비활성화하고,
        // 특정 경로에 대한 인가 규칙을 정의하며, 세션 관리를 STATELESS로 설정하여 보안을 강화
    }
}