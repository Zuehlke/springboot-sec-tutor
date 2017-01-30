package com.zuehlke.bgre.security.controller;

import com.zuehlke.bgre.security.domain.User;
import com.zuehlke.bgre.security.service.UserService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
public class UserControllerAccessTest {
    private MockMvc mvc;

    @Autowired
    private WebApplicationContext context;

    @MockBean
    private UserService userService;

    @Before
    public void mockUserService(){
        ArrayList<User> users = new ArrayList<>();
        users.add(new UserBuilder().withUsername("user1").withRole("USER").build());
        when(userService.findAll()).thenReturn(users);
    }

    @Before
    public void setupMockMvc(){
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    public void getUsers_asRoleUser_accessDenied() throws Exception {
        mvc.perform(get("/users"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"USER", "ADMIN"})
    public void getUsers_asRoleAdmin_returnsUsers() throws Exception {
        mvc.perform(get("/users"))
                .andExpect(status().isOk())
                .andExpect(content().json("[{\"username\":\"user1\",\"roles\":[\"USER\"]}]"));
    }

    @Test
    @WithMockUser(username = "selfUser", roles = {"USER"})
    public void getSelf_asRoleUser_returnsMockedUserFromAnnotation() throws Exception {
        mvc.perform(get("/users/self"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"username\":\"selfUser\",\"roles\":[\"ROLE_USER\"]}"));
    }

    @Test
    @WithMockUser(username = "selfUser", roles = {"UNVERIFIED"})
    public void getSelf_asRoleUnverified_accessDenied() throws Exception {
        mvc.perform(get("/users/self"))
                .andExpect(status().isForbidden());
    }

}
