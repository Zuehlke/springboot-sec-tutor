package com.zuehlke.bgre.security.controller;

import com.zuehlke.bgre.security.domain.Role;
import com.zuehlke.bgre.security.domain.User;
import com.zuehlke.bgre.security.service.UserService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;
import java.util.HashSet;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
public class UserControllerTest {

    private MockMvc mockMvc;

    @Mock
    private UserService userService;

    @InjectMocks
    private UserController userController;

    @Before
    public void setupMvc(){
        mockMvc =  MockMvcBuilders
                .standaloneSetup(userController)
                .build();
    }

    @Test
    public void getHello() throws Exception {
        ArrayList<User> users = new ArrayList<>();
        User testUser = mockUser("username", "ADMIN");
        users.add(testUser);
        when(userService.findAll()).thenReturn(users);
        mockMvc.perform(get("/users"))
                .andExpect(status().isOk())
                .andExpect(content().string("[{\"username\":\"username\",\"roles\":[\"ADMIN\"]}]"));
    }

    private User mockUser(String username, String role) {
        User testUser = new User();
        testUser.setUsername(username);
        HashSet<Role> roles = new HashSet<>();
        Role adminRole = new Role();
        adminRole.setName(role);
        roles.add(adminRole);
        testUser.setRoles(roles);
        return testUser;
    }
}