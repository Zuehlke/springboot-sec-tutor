package com.zuehlke.bgre.security.controller;

import com.zuehlke.bgre.security.domain.User;
import com.zuehlke.bgre.security.service.UserService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.ArrayList;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
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
    public void getUsers_havingOneUser_JSONisReturned() throws Exception {
        ArrayList<User> users = new ArrayList<>();
        User testUser = new UserBuilder().withUsername("username").withRole("ADMIN").build();
        users.add(testUser);
        when(userService.findAll()).thenReturn(users);
        mockMvc.perform(get("/users"))
                .andExpect(status().isOk())
                .andExpect(content().string("[{\"username\":\"username\",\"roles\":[\"ADMIN\"]}]"));
    }
}