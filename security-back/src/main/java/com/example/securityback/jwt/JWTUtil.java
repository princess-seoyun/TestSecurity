package com.example.securityback.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    // 각 메소드는 토큰을 전달받아서 내부 Jwts.parser 를 이용해서 내부 데이터를 확인해서 return 해줌
    // verifyWith 메소드를 통해 우리가 가진 시크릿 키가 우리 서버에서 생성되었는지 확인함
    // parseSignedClaims 를 통해 Claims 를 확인 후
    // 특정한 데이터를 가져올 것이고(get 메소드 사용)
    // 마지막은 String 타입으로 가져오라는 의미
    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    // 토큰이 만료되었는지 확인하는 메소드
    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 로그인이 성공했을 때 토큰을 생성해서 응답하는 토큰 생성 메소드
    public String createJwt(String username, String role, Long expiredMs) { // 유저 이름, 역할, 토큰 시간 인자로 넣어줌

        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 언제 발행되었는지 발행 시간을 issuedAt 메소드 활용해서 넣어줌
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 언제 토큰이 소멸될 것인지
                .signWith(secretKey)
                .compact();
    }
}
