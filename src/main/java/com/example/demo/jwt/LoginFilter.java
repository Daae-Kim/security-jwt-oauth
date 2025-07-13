package com.example.demo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    //loginform 을 비활성화하며 usernamePasswordAuthenticationFilter 도 함께 비활성화 되어 직접 커스텀, 사용
    // 목적 : username, password 뽑기

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출 (ObtainUsername, ObtainPassword 메소드 사용)
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //인증 진행 -> authenticationManager 한테 username, password DTO(usernamePasswordAuthenticationToken) 로 던져주고, 인증 받음(db 조회)
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        return authenticationManager.authenticate(authToken); // 검증 진행 (db 에서 회원정보 -> user details에서 회원 정보 받고, 검증 진행)

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,Authentication authentication){

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){}
}
