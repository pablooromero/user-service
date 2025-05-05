package com.user_service.user_service.services;

import com.user_service.user_service.models.UserEntity;

public interface OAuthService {
    String processOAuthLogin(String email, String name, String lastName);

    UserEntity findOrCreateByEmail(String email, String name, String lastName);
}
