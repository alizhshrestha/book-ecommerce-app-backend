package com.sha.springbootbookseller;

import com.sha.springbootbookseller.model.Role;
import com.sha.springbootbookseller.model.User;
import com.sha.springbootbookseller.repository.IUserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;

@SpringBootApplication
public class SpringBootBookSellerApplication {

    private IUserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    public SpringBootBookSellerApplication(IUserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringBootBookSellerApplication.class, args);
    }

    @Bean
    CommandLineRunner commandLineRunner(){
        return args -> {
            User user = new User();
            user.setUsername("root");
            user.setPassword(passwordEncoder.encode("root"));
            user.setName("Alish Shrestha");
            user.setRole(Role.ADMIN);
            user.setCreateTime(LocalDateTime.now());

            userRepository.save(user);

        };
    }

}
