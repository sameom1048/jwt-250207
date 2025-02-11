package com.example.jwt.global;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.exception.ServiceException;
import com.example.jwt.global.security.SecurityUser;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

// Request, Response, Session, Cookie, Header
@Component
@RequiredArgsConstructor
@RequestScope
public class Rq {

    private final HttpServletRequest request;
    private final MemberService memberService;
    private final HttpServletResponse response;

    public void setLogin(Member actor) {

        // 유저 정보 생성
        UserDetails user = new SecurityUser(actor.getId(), actor.getUsername(), "", actor.getAuthorities());

        // 인증 정보 저장소
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
        );
    }

    public Member getActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication == null) {
            throw new ServiceException("401-2", "로그인이 필요합니다.");
        }

        Object principal = authentication.getPrincipal();

        if(!(principal instanceof SecurityUser)) {
            throw new ServiceException("401-3", "잘못된 인증 정보입니다");
        }

        SecurityUser user = (SecurityUser) principal;

        return Member.builder()
                .id(user.getId())
                .username(user.getUsername())
                .build();
    }

    public String getHeader(String name) {
        return request.getHeader(name);
    }

    public String getValueFromCookie(String name) {
        Cookie[] cookies = request.getCookies();
        if(cookies == null) {
            return null;
        }
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals(name)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public void setHeader(String name, String value) {
        response.setHeader(name, value);
    }

    public void addCookie(String name, String value) {
        Cookie accsessTokenCookie = new Cookie(name, value);
        accsessTokenCookie.setDomain("localhost");
        accsessTokenCookie.setPath("/");
        accsessTokenCookie.setHttpOnly(true);
        accsessTokenCookie.setSecure(true);
        accsessTokenCookie.setAttribute("SameSite", "Strict");
        response.addCookie(accsessTokenCookie);
    }
}