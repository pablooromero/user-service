package com.user_service.user_service.exceptions;

import org.springframework.http.HttpStatus;

public class UserException extends RuntimeException {
    private HttpStatus httpStatus;

    public UserException(String message) {
        super(message);
    }

    public UserException(String message, HttpStatus code) {
        super(message);
        this.httpStatus=code;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}