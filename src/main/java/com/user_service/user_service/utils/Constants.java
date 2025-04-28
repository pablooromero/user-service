package com.user_service.user_service.utils;

public class Constants {
    public static final String USR_NOT_EXIST="The user doesn't exists";
    public static final String EMPTY_PASS="The password its empty";
    public static final String EXIST_EMAIL="The email already exists";
    public static final String INV_EMAIL="The email its invalid";
    public static final String SUC_DEL_USER = "Successful deleted user";
    public static final String[] URL_MAILS = {"@hotmail.com","outlook.com","gmail.com"};
    public static final String SUC_REG = "Successful register";
    public static final String BODY_MAIL = "Thanks for using our application!. \nHave a nice day ;)\n";
    public static final String INV_CRED = "Invalid credentials";
    public static final String CONFIRM ="The user was confirmed";
    public static final String NOT_ACTIVE = "The user is not confirmed";

    //LOGS CONSTANTS
    //AUTH SERVICE
    public static final String AUTHENTICATING_USER = "Attempting to authenticate user with email: ";
    public static final String USER_LOGGED_SUCCESSFULLY = "User logged in successfully: ";
    public static final String CREATING_USER = "Creating user: ";
    public static final String CREATED_SUCCESSFULLY = "User created successfully: ";
    public static final String SENDING_REGISTRATION_MAIL = "Sending registration email to: ";
    public static final String SEND_EMAIL_SUCCESSFULLY = "Email sent successfully to: ";

    //USER SERVICE
    public static final String SAVING_USER = "Saving user: ";
    public static final String USER_SAVED_SUCCESSFULLY = "User saved successfully: ";
    public static final String USER_NOT_FOUND = "User not found with ID: ";
    public static final String USER_NOT_FOUND_WITH_EMAIL = "User not found with email: ";
    public static final String GET_ALL_USERS = "Retrieving all users";
    public static final String GET_ALL_USERS_SUCCESSFULLY = "Retrieved all users successfully";
    public static final String GET_USER_SUCCESSFULLY = "User retrieved successfully";
    public static final String VALIDATE_USER = "Validating user with ID: ";
    public static final String VALIDATE_USER_SUCCESSFULLY = "User validated successfully";
    public static final String GET_USER = "Retrieving user with ID: ";
    public static final String GET_USER_BY_EMAIL = "Retrieving user with email: ";
    public static final String GET_USER_BY_EMAIL_SUCCESSFULLY = "Returning user id by email: ";
    public static final String CREATING_ADMIN = "Creating admin: ";
    public static final String ADMIN_CREATED_SUCCESSFULLY = "Admin created successfully";
    public static final String DELETING_USER = "Deleting user with ID: ";
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully with ID: ";
    public static final String UPDATING_USER = "Updating user with ID: ";
    public static final String UPDATE_USER_SUCCESSFULLY = "User updated successfully with email: ";
    public static final String CHANGING_PASSWORD = "Changing password for authenticated user";
    public static final String CURRENT_PASSWORD_INCORRECT = "Current password is incorrect for user: ";
    public static final String NEW_PASSWORD_TOO_SHORT = "New password is too short for user: ";
    public static final String NEW_PASSWORD_SAME = "New password is the same as the current password for user: ";
    public static final String PASSWORD_UPDATED_SUCCESSFULLY = "Password updated successfully for user: ";
}

