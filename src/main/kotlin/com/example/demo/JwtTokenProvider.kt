package com.example.demo

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.util.*
import java.util.stream.Collectors
import javax.crypto.SecretKey

@Component
class JwtTokenProvider() {

    @Value("\${app.jwt.expireTime}")
    private var jwtExpireTime: Int = 604800000

    private val logger: Logger = LoggerFactory.getLogger(this::class.java);

    private lateinit var key: SecretKey

    @Bean
    fun jwtSecretKey(): SecretKey {
        return Keys.secretKeyFor(SignatureAlgorithm.HS512)
    }


    fun generateToken(authentication: Authentication): String {
        val currentDate = Date()
        val expireDate = currentDate.time + jwtExpireTime
        val authorities = authentication.authorities.stream()
                .map { obj: GrantedAuthority -> obj.authority }
                .collect(Collectors.joining(","))

        return Jwts.builder()
                .claim("authorities", authorities)
                .setSubject(authentication.name)
                .setIssuedAt(Date())
                .setExpiration(Date(expireDate))
                .signWith(jwtSecretKey())
                .compact()
    }

    fun validateToken(token: String): Boolean {
        try {
            Jwts.parser()
                    .setSigningKey(jwtSecretKey())
                    .parseClaimsJws(token)
            return true
        } catch (exception: SignatureException) {
            logger.error(exception.toString())
        } catch (exception: MalformedJwtException) {
            logger.error(exception.toString())
        } catch (exception: ExpiredJwtException) {
            logger.error(exception.toString())
        } catch (exception: UnsupportedJwtException) {
            logger.error(exception.toString())
        } catch (exception: IllegalArgumentException) {
            logger.error(exception.toString())
        } catch (exception: IllegalArgumentException) {
        }
        return false
    }

    fun getAuthentication(token: String): Authentication? {
        val claims = Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(token)
                .body

        val authorities: Collection<GrantedAuthority?> = Arrays.stream(claims.toString().split(",").toTypedArray())
                .map { role: String? -> SimpleGrantedAuthority(role) }
                .collect(Collectors.toList())

        val principal = User(claims.subject, "", authorities)

        return UsernamePasswordAuthenticationToken(principal, token, authorities)
    }
}