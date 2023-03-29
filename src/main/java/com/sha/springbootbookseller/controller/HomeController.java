package com.sha.springbootbookseller.controller;

import com.sha.springbootbookseller.model.User;
import com.sha.springbootbookseller.service.IUserService;
import com.sha.springbootbookseller.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    private IUserService userService;

    public HomeController(IUserService userService) {
        this.userService = userService;
    }

    @GetMapping("/home")
    public String home(){
        return "Hello World!";
    }

    @PostMapping("/users")
    public ResponseEntity<User> addUser(@RequestBody User user){
        User createdUser = userService.saveUser(user);
        return ResponseEntity.ok(createdUser);
    }
}
