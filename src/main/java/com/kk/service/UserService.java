package com.kk.service;

import com.kk.exception.UserException;
import com.kk.modal.User;

public interface UserService {
    public User findUserById(Long userId) throws UserException;
    public User findUserProfileByJwt(String jwt) throws UserException;

}
