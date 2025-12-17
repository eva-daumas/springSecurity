package com.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig implements WebMvcConfigurer {


    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // Route vers la page d'accueil
        registry.addViewController("/").setViewName("home");
        registry.addViewController("/home").setViewName("home");

        // Route vers la page de connexion
        registry.addViewController("/login").setViewName("login");

        // Route vers la page hello/secured
        registry.addViewController("/hello").setViewName("hello");
    }
}