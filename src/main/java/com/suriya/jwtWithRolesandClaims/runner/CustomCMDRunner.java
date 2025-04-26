package com.suriya.jwtWithRolesandClaims.runner;

import com.suriya.jwtWithRolesandClaims.entity.Role;
import com.suriya.jwtWithRolesandClaims.entity.User;
import com.suriya.jwtWithRolesandClaims.repository.RoleRepository;
import com.suriya.jwtWithRolesandClaims.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.Set;

@Configuration
public class CustomCMDRunner {

    @Bean
    CommandLineRunner initRoles(RoleRepository roleRepository) {
        return args -> {
            if (roleRepository.findByName("ROLE_USER").isEmpty()) {
                Role roleUser = new Role();
                roleUser.setName("ROLE_USER");
                roleRepository.save(roleUser);
                System.out.println("✅ ROLE_USER created");
            }

            if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
                Role roleAdmin = new Role();
                roleAdmin.setName("ROLE_ADMIN");
                roleRepository.save(roleAdmin);
                System.out.println("✅ ROLE_ADMIN created");
            }
        };
    }
}
