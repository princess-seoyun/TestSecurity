package com.example.securityback.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // Spring Security를 사용하는 웹 보안을 활성화
public class SecurityConfig {

    // Spring Security에서 제공하는 비밀번호 인코딩을 위한 클래스
    // 사용자의 비밀번호를 안전하게 해싱(hash)하기 위해 사용되는 클래스
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    // Spring Security에서 요청에 대한 보안 필터 체인을 구성
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

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