package com.ead.notification.configs.security;

import com.ead.authuser.models.UserModel;
import com.ead.authuser.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserModel userModel = userRepository.findUserByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: "+username));
        return UserDetailsImpl.build(userModel);
    }

    public UserDetails loadUserByUserId(UUID userId) throws UsernameNotFoundException {
        UserModel userModel = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: "+userId));
        return UserDetailsImpl.build(userModel);
    }
}
