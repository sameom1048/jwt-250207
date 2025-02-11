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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if(!authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authToken = authorizationHeader.substring("Bearer ".length());

        String[] tokenBits = authToken.split(" ", 2);

        if(tokenBits.length < 2) {
            filterChain.doFilter(request, response);
            return;
        }

        String apiKey = tokenBits[0];
        String accessToken = tokenBits[1];

        // accessToken 인증 방식
        Optional<Member> opMember = memberService.getMemberByAccessToken(accessToken);


        if(opMember.isEmpty()) {

            // 재발급
            Optional<Member> opApiMember = memberService.findByApiKey(apiKey);

            if(opApiMember.isEmpty()) {
                filterChain.doFilter(request, response);
                return;
            }

            String newAuthToken = memberService.getAuthToken(opApiMember.get());
            response.addHeader("Authorization", "Bearer " + newAuthToken);

            Member actor = opApiMember.get();
            rq.setLogin(actor);

            filterChain.doFilter(request, response);
            return;
        }

        Member actor = opMember.get();
        rq.setLogin(actor);

        filterChain.doFilter(request, response);
    }
}