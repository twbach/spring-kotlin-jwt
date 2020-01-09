package com.example.demo

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.util.StringUtils
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class JwtAuthenticationFilter: OncePerRequestFilter() {
    @Autowired
    lateinit var tokenProvider: JwtTokenProvider

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        try {
            val jwt = getJwtFromRequest(request)
            if (jwt != null && tokenProvider.validateToken(jwt)) {
                val authentication = tokenProvider.getAuthentication(jwt)

                SecurityContextHolder.getContext().authentication = authentication
            }

        } catch (exception: Exception) {
            logger.error(exception.toString())
        }
        filterChain.doFilter(request, response)
    }

    private fun getJwtFromRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("Authorization")
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length)
        }
        return null
    }

}
