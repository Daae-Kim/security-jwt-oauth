package com.example.demo.jwt;

import com.example.demo.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Iterator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    //loginform 을 비활성화하며 usernamePasswordAuthenticationFilter 도 함께 비활성화 되어 직접 커스텀, 사용
    // 목적 : username, password 뽑기

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출 (ObtainUsername, ObtainPassword 메소드 사용)
        String username = obtainUsername(request);
        System.out.println("obtainUserName : " + username);
        String password = obtainPassword(request);

        //인증 진행 -> authenticationManager 한테 username, password DTO(usernamePasswordAuthenticationToken) 로 던져주고, 인증 받음(db 조회)
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        System.out.println("authToken : " + authToken);
        return authenticationManager.authenticate(authToken); // 검증 진행 (db 에서 회원정보 -> user details에서 회원 정보 받고, 검증 진행)

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,Authentication authentication){
        //성공시 jwt발급
        //정보 뽑아내기
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal(); // 특정 유저 확인
        String username = userDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();

        String role = grantedAuthority.getAuthority();

        //정보로 jwt 토큰 생성
        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        //http 인증 방식은 RFC 7235 정의에 따라 인증헤더 형태를 가져야 한다.
        response.addHeader("Authorization", "Bearer " + token);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){
        response.setStatus(401);
    }
}
