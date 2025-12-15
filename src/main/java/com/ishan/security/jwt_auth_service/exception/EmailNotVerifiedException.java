package com.ishan.security.jwt_auth_service.exception;

public class EmailNotVerifiedException extends RuntimeException {
    public EmailNotVerifiedException() {
        super("Email not verified");
    }
}
