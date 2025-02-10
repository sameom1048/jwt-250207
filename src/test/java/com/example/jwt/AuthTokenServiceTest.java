package com.example.jwt;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.domain.member.member.service.AuthTokenService;
import com.example.jwt.domain.member.member.service.MemberService;
import com.example.jwt.standard.util.Ut;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {

    @Autowired
    private AuthTokenService authTokenService;
    @Autowired
    private MemberService memberService;

    SecretKey secretKey = Keys.hmacShaKeyFor("abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890".getBytes());

    @Test
    @DisplayName("AuthTokenService 생성")
    void init() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jwt 생성")
    void createToken() {
        int expireSeconds = 60 * 60 * 24 * 365;
        Map<String, Object> originPayload = Map.of("name", "john", "age", 23);

        String jwtStr = Ut.Jwt.createToken(secretKey, expireSeconds, originPayload);
        assertThat(jwtStr).isNotBlank();
        Map<String, Object> parsedPayload = Ut.Jwt.getPayload(secretKey, jwtStr);

        assertThat(parsedPayload).containsAllEntriesOf(originPayload);
    }

    @Test
    @DisplayName("access token 생성")
    void accessToken() {

        // jwt -> access token jwt
        Member member = memberService.findByUsername("user1").get();
        String accessToken = authTokenService.genAccessToken(member);

        assertThat(accessToken).isNotBlank();

        System.out.println("accessToken = " + accessToken);
    }

    @Test
    @DisplayName("jwt valid check")
    void checkValid() {

        Member member = memberService.findByUsername("user1").get();
        String accessToken = authTokenService.genAccessToken(member);
        boolean isValid = Ut.Jwt.isValidToken(secretKey, accessToken);
        assertThat(isValid).isTrue();

        Map<String, Object> parsedPayload = authTokenService.getPayload(secretKey, accessToken);

        assertThat(parsedPayload).containsAllEntriesOf(
                Map.of("id", member.getId(), "username", member.getUsername())
        );

    }

}