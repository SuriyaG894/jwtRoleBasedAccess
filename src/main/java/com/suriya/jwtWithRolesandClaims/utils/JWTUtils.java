package com.suriya.jwtWithRolesandClaims.utils;

import com.suriya.jwtWithRolesandClaims.entity.Role;
import com.suriya.jwtWithRolesandClaims.entity.User;
import com.suriya.jwtWithRolesandClaims.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JWTUtils {

    @Autowired
    private UserRepository userRepository;

    private String secret = "This is secret key which is gonn@ be used @s sccret###";
    private SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));


    public String generateRefreshToken(String username){

        Optional<User> user = userRepository.findByUsername(username);
        Set<Role> roles = user.get().getRole();

        return Jwts
                .builder()
                .signWith(secretKey)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+1000*60*2))
                .claim("email",username)
                .claim("roles",roles.stream().map(Role::getName).collect(Collectors.joining(",")))
                .compact();
    }

    public String generateToken(String username){

        Optional<User> user = userRepository.findByUsername(username);
        Set<Role> roles = user.get().getRole();

        return Jwts
                .builder()
                .signWith(secretKey)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+1000*60))
                .claim("email",username)
                .claim("roles",roles.stream().map(Role::getName).collect(Collectors.joining(",")))
                .compact();
    }
    
    public Claims extractClaims(String token){
        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token){
        System.out.println(extractClaims(token).getSubject()+"-------------username");
        return extractClaims(token).getSubject();
    }

    public Set<String> extractRoles(String token){
        return Arrays.stream(extractClaims(token).get("roles",String.class).split(",")).collect(Collectors.toSet());
    }

    public boolean isTokenExpired(String token){
        return extractClaims(token).getExpiration().before(new Date());
    }

}
