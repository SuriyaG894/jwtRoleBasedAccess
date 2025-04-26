package com.suriya.jwtWithRolesandClaims.filter;


import com.suriya.jwtWithRolesandClaims.service.CustomDetailsService;
import com.suriya.jwtWithRolesandClaims.utils.JWTUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;


@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JWTUtils jwtUtils;
    private final CustomDetailsService customDetailsService;

    public JwtFilter(JWTUtils jwtUtils, CustomDetailsService customDetailsService) {
        this.jwtUtils = jwtUtils;
        this.customDetailsService = customDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        String token = null;
        String username = null;
        if(header!=null  && header.startsWith("Bearer ")){
            token = header.substring(7);
            username = jwtUtils.extractUsername(token);
            System.out.println(username+"=================================");
            System.out.println(SecurityContextHolder.getContext().getAuthentication()!=null);
        }

        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = customDetailsService.loadUserByUsername(username);
            if(!jwtUtils.isTokenExpired(token) && userDetails.getUsername().equals(jwtUtils.extractUsername(token))){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails.getUsername(),userDetails.getPassword(),userDetails.getAuthorities());
                System.out.println("User Authority: "+userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request,response);
    }
}
