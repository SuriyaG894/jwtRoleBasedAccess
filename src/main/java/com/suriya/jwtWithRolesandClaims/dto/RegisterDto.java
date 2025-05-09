package com.suriya.jwtWithRolesandClaims.dto;


import java.util.Set;

public class RegisterDto {

    private String username;
    private String password;
    private Set<String> role;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRole() {
        return role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
