package com.example.demo.jwt;


import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil {
    //jwt 검증, 토큰 생성

    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}")String secret){
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    //jwt parser 로 토큰 검증 -> 우리서버에서 생성된 토큰인지 확인 -> 데이터 획득(username)
    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }


    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    //토큰생성 메서드
    public String createJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username", username) // payload 에 Username, role 값 넣음
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) //토큰 발행시간 넣어줌
                .expiration(new Date(System.currentTimeMillis()+expiredMs)) // 토큰 발행 시간 + expiredMs
                .signWith(secretKey).compact(); // secretKey 를 활용해서 시그니처 생성
    }

}
