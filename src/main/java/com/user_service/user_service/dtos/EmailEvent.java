package com.user_service.user_service.dtos;

public record EmailEvent (String to, String subject, String body) {}