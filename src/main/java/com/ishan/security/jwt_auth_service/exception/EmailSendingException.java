package com.ishan.security.jwt_auth_service.exception;

public class EmailSendingException extends RuntimeException{

    public EmailSendingException() {
        super("Failed to send email");
    }

    public EmailSendingException(String message) {
        super(message);
    }

    public EmailSendingException(String message, Throwable cause) {
        super(message, cause);
    }
}
