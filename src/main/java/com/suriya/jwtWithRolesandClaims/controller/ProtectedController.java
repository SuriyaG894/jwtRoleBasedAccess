package com.suriya.jwtWithRolesandClaims.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class ProtectedController {

    @PostMapping("/home/{id}")
    public String homePage(@PathVariable("id")int id){
        return "Home Page Accessed "+id;
    }
}
