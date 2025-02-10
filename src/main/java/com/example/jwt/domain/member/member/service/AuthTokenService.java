package com.example.jwt.domain.member.member.service;

import com.example.jwt.domain.member.member.entity.Member;
import com.example.jwt.standard.util.Ut;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthTokenService {

    @Value("${custom.jwt.secret-key}")
    private String keyString;

    @Value("${custom.jwt.expire-seconds}")
    private int expireSeconds;

    public String genAccessToken(Member member) {

        return Ut.Jwt.createToken(
                keyString,
                expireSeconds,
                Map.of("id", member.getId(), "username", member.getUsername())
        );
    }

    public Map<String, Object> getPayload(String token) {
        Map<String, Object> payload = Ut.Jwt.getPayload(keyString, token);

        if(payload == null) return null;

        Number idNo = (Number)payload.get("id");
        long id = idNo.longValue();

        String username = (String)payload.get("username");

        return Map.of("id", id, "username", username);
    }
}