package com.zuehlke.bgre.security.config;

import com.zuehlke.bgre.security.domain.Role;
import com.zuehlke.bgre.security.domain.User;
import com.zuehlke.bgre.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserService userService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService
                .getByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " not found"));
        HashSet<GrantedAuthority> authorities = new HashSet<>();
        if(user.getRoles() != null) {
            user.getRoles().stream()
                    .map(Role::getName)
                    .map(SimpleGrantedAuthority::new)
                    .forEach(authorities::add);
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPasswordHash(), authorities);
    }
}
