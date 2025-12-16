package com.ishan.security.jwt_auth_service.exception;

public class ResendEmailCooldownException extends RuntimeException {

    public ResendEmailCooldownException(String message) {
        super(message);
    }
}
