package com.suriya.jwtWithRolesandClaims.service;

import com.suriya.jwtWithRolesandClaims.dto.JwtResponse;
import com.suriya.jwtWithRolesandClaims.dto.LoginDto;
import com.suriya.jwtWithRolesandClaims.dto.RegisterDto;
import com.suriya.jwtWithRolesandClaims.entity.Role;
import com.suriya.jwtWithRolesandClaims.entity.User;
import com.suriya.jwtWithRolesandClaims.repository.RoleRepository;
import com.suriya.jwtWithRolesandClaims.repository.UserRepository;
import com.suriya.jwtWithRolesandClaims.utils.JWTUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtils jwtUtils;

    public ResponseEntity<String> registerUser(RegisterDto registerDto)  {
        if(userRepository.findByUsername(registerDto.getUsername()).isPresent()){
            return new ResponseEntity<>("User already exists",HttpStatus.BAD_REQUEST);
        }
        User user = new User();
        user.setUsername(registerDto.getUsername());
        System.out.println(registerDto.getPassword()+" encodedPass: "+passwordEncoder.encode(registerDto.getPassword()));
        user.setPassword(passwordEncoder.encode(registerDto.getPassword()));
        for (String roleName : registerDto.getRole()) {
            Optional<Role> existingRole = roleRepository.findByName(roleName);
            if (existingRole.isPresent()) {
                user.getRole().add(existingRole.get());  // Attach existing role
            } else {
                return new ResponseEntity<>("Invalid role", HttpStatus.FORBIDDEN);
            }
        }
        userRepository.save(user);

        return new ResponseEntity<>("User registered Successfully",HttpStatus.CREATED);
    }

    public ResponseEntity<?> login(LoginDto loginDto){
        try{
            System.out.println(loginDto.getUsername()+" - "+loginDto.getPassword() );
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword()));
        }
        catch(Exception e){
            return new ResponseEntity<>("Invalid Username and Password"+e,HttpStatus.UNAUTHORIZED);
        }
        String accessToken = jwtUtils.generateToken(loginDto.getUsername());
        String refreshToken = jwtUtils.generateRefreshToken(loginDto.getUsername());
        JwtResponse response = new JwtResponse(accessToken,refreshToken);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    public ResponseEntity<?> validateRefreshToken(String token) {
        String username = jwtUtils.extractUsername(token);
        if(jwtUtils.isTokenExpired(token)){
            return new ResponseEntity<>("Token Expired. Login again ",HttpStatus.UNAUTHORIZED);
        }
        else {
            userRepository.findByUsername(username);
            String accessToken = jwtUtils.generateToken(username);
            String refreshToken = jwtUtils.generateRefreshToken(username);
            JwtResponse response = new JwtResponse(accessToken,refreshToken);
            return new ResponseEntity<>(response,HttpStatus.OK);
        }
    }


}
