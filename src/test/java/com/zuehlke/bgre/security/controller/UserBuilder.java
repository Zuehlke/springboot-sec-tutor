package com.zuehlke.bgre.security.controller;

import com.zuehlke.bgre.security.domain.Role;
import com.zuehlke.bgre.security.domain.User;

import java.util.*;
import java.util.stream.Collectors;

public class UserBuilder {
    private String username;
    private List<String> roles = new ArrayList<>();

    public UserBuilder withUsername(String username) {
        this.username = username;
        return this;
    }

    public UserBuilder withRole(String role){
        roles.add(role);
        return this;
    }

    public User build(){
        User testUser = new User();
        testUser.setUsername(username);
        Set<Role> roles = this.roles.stream().map(roleName -> {
            Role role = new Role();
            role.setName(roleName);
            return role;
        }).collect(Collectors.toSet());
        testUser.setRoles(roles);
        return testUser;
    }
}
