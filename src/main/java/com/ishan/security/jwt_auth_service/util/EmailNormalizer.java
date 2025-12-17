package com.ishan.security.jwt_auth_service.util;

import org.springframework.stereotype.Component;

@Component
public class EmailNormalizer {

    public String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
