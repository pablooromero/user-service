package com.user_service.user_service.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class ExceptionHandlers {

    @ExceptionHandler(UserException.class)
    public ResponseEntity<String> orderExceptionHandler(UserException userException){
        if (userException.getHttpStatus()!=null)
            return new ResponseEntity<>(userException.getMessage(), userException.getHttpStatus());
        else
            return new ResponseEntity<>(userException.getMessage(), HttpStatus.BAD_REQUEST);
    }
}
