package com.jyalla.demo.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class CustomUserDetails implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles = new ArrayList<>();
        if (username.equals("admin")) {
            roles = Arrays.asList(new SimpleGrantedAuthority("ADMIN"));
            return new User(username, "$2a$04$hhYIQ6yRv8./To976dZjZepiQJZ4Z7GFJ/l.tiCLcATLBaGCDr9Ta", roles);
        }
        if (username.equals("user")) {
            roles = Arrays.asList(new SimpleGrantedAuthority("USER"));
            return new User(username, "$2a$04$JyjRqARNHq7PhdCc2IzuuuHkZ5dPG7oSZjjU2E2Kk/epQBbf0bWfK", roles);
        }
        throw new UsernameNotFoundException("User not found with Username " + username);
    }

}
