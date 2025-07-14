package com.example.demo.jwt;

import com.example.demo.dto.CustomUserDetails;
import com.example.demo.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

//요청에 대해 한번만 동작하는 OncePerRequestFilter
public class JWTFilter extends OncePerRequestFilter {


    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    //jwt 검증필터, contextholder 에 담기
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //request 에서 Authorization 키값을 가지는 헤더를 찾음
        String authorization= request.getHeader("Authorization");

        //authorization 헤더 검증
        if(authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("toekn is null");
            filterChain.doFilter(request, response); // 다음 필터로 넘겨줌
            return;
        }

        //토큰 분리 후 소멸 시간 검증
        //bearer 제거
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if(jwtUtil.isExpired(token)){
            System.out.println("token is expired");
            filterChain.doFilter(request, response);

            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword"); // 비밀번호 값은 token 에 없다. contextHolder 에 비밀번호를 담을 필요가 없다.
        userEntity.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity); // UserDetails 만들기
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        System.out.println("authToken = " + authToken);
        System.out.println("customUserDetails.getAuthorities() = " + customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authToken);
        System.out.println("jwtfilter : authToken = " + authToken);// contextHolder 에 담아서 유저 session 생성 -> 특정 경로에 접근 가능

        filterChain.doFilter(request, response);

    }
}
