package com.zuehlke.bgre.security.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/hello")
public class HelloController {

    @CrossOrigin(origins = "http://myfrontend.com")
    @RequestMapping(method = RequestMethod.GET)
    public String getHello(@RequestParam(required = false) String name) {
        String welcomeText = "Welcome";
        if (name != null && !name.isEmpty()) {
            welcomeText += " " + name;
        }
        return welcomeText;
    }

    @RequestMapping(method = RequestMethod.POST, consumes = {MediaType.APPLICATION_JSON_VALUE})
    public String postHello(@RequestBody(required = false) String name) {
        String welcomeText = "Welcome";
        if (name != null && !name.isEmpty()) {
            welcomeText += " " + name;
        }
        return welcomeText;
    }
}
