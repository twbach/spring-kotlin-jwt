package com.example.demo

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

class SecurityConfig(
        val tokenProvider: JwtTokenProvider
) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
        http
                .authorizeRequests()
                .and()
                .apply(securityConfigurationAdapter())

    }

    private fun securityConfigurationAdapter(): JwtConfigurationAdapter {
        return JwtConfigurationAdapter(tokenProvider)
    }
}