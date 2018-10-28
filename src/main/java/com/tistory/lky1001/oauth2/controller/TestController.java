package com.tistory.lky1001.oauth2.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/")
    public String main() {
        return "main";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/secure")
    @Secured({"ROLE_USER"})
    public String secure() {
        return "secure";
    }
}
