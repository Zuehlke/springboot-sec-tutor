package com.zuehlke.bgre.security.controller;

import com.zuehlke.bgre.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(method = RequestMethod.GET)
    public List<UserDTO> getUsers() {
        return userService.findAll().stream().map(UserDTO::from).collect(Collectors.toList());
    }

    @RequestMapping(value = "/self",method = RequestMethod.GET)
    public UserDTO getLogedInUser(@AuthenticationPrincipal User user){
        return UserDTO.from(user);
    }
}
