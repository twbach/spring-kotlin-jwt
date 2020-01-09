package com.example.demo

import org.springframework.security.config.annotation.SecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

class JwtConfigurationAdapter(
        private val tokenProvider: JwtTokenProvider
): SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>() {


    override fun configure(builder: HttpSecurity) {
        builder.addFilterBefore(
                JwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter::class.java
        )
    }



}
