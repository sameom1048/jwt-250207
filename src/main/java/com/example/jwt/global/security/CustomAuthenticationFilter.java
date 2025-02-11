package com.example.jwt.global.security;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.global.Rq;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationFilter extends OncePerRequestFilter {

    private final Rq rq;
    private final MemberService memberService;

    private boolean isAuthorizationHeader() {
        String authorizationHeader = rq.getHeader("Authorization");

        if (authorizationHeader == null) {
            return false;
        }

        return authorizationHeader.startsWith("Bearer ");
    }

    private String[] getAuthTokenFromRequest() {

        if (isAuthorizationHeader()) {

            String authorizationHeader = rq.getHeader("Authorization");
            String authToken = authorizationHeader.substring("Bearer ".length());

            String[] tokenBits = authToken.split(" ", 2);

            if (tokenBits.length < 2) {
                return null;
            }

            return new String[]{tokenBits[0], tokenBits[1]};
        }

        String accessToken = rq.getValueFromCookie("accessToken");
        String apiKey = rq.getValueFromCookie("apiKey");

        if (accessToken == null || apiKey == null) {
            return null;
        }

        return new String[]{apiKey, accessToken};

    }

    private Member refreshAccessToken(String accessToken, String apiKey) {

        Optional<Member> opAccMember = memberService.getMemberByAccessToken(accessToken);

        if (opAccMember.isEmpty()) {
            Optional<Member> opRefMember = memberService.findByApiKey(apiKey);

            if (opRefMember.isEmpty()) {
                return null;
            }

            String newAccessToken = memberService.genAccessToken(opRefMember.get());
            rq.setHeader("Authorization", "Bearer " + newAccessToken);
            rq.addCookie("accessToken", newAccessToken);

            return opRefMember.get();
        }

        return opAccMember.get();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String[] tokens = getAuthTokenFromRequest();

        if (tokens == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = tokens[0];
        String accessToken = tokens[1];

        // 재발급 코드
        Member actor = refreshAccessToken(accessToken, apiKey);
        if (actor == null) {
            filterChain.doFilter(request, response);
            return;
        }
        rq.setLogin(actor);

        filterChain.doFilter(request, response);
    }
}