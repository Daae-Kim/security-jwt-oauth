package com.example.demo.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody // 특정 문자열 반환
public class MainController {

    @GetMapping("/")
    public String mainP() {
        return "Main Controller";
    }

}
