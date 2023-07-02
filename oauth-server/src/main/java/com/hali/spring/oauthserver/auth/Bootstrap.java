package com.hali.spring.oauthserver.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@RequiredArgsConstructor
@Component
public class Bootstrap  implements CommandLineRunner {

    private final UserRepository userRepository;
    private final ScopeRepository scopeRepository;
    private final UserScopeRepository userScopeRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    public void run(String... args) throws Exception {

        ScopeEntity readScope = new ScopeEntity();
        readScope.setName("read");
        ScopeEntity readSavedScope = scopeRepository.save(readScope);

        ScopeEntity writeScope = new ScopeEntity();
        writeScope.setName("read");
        ScopeEntity writeScopeSavedScope = scopeRepository.save(writeScope);

        ScopeEntity adminScope = new ScopeEntity();
        adminScope.setName("read");
        ScopeEntity adminScopeSavedScope = scopeRepository.save(adminScope);


        UserEntity user1 = getUserEntity("User 1","user1","user1@example.com");
        userRepository.save(user1);

        UserEntity user2 =  getUserEntity("User 2","user2","user2@example.com");
        userRepository.save(user2);

        UserEntity user3 = getUserEntity("User 3","user3","user3@example.com");
        userRepository.save(user3);

        UserScope user1ReadScope = new UserScope(user1, readScope);
        UserScope user1WriteScope = new UserScope(user1, writeScope);
        UserScope user2WriteScope = new UserScope(user2, writeScope);
        UserScope user3AdminScope = new UserScope(user3, adminScope);

        userScopeRepository.save(user1ReadScope);
        userScopeRepository.save(user1WriteScope);
        userScopeRepository.save(user2WriteScope);
        userScopeRepository.save(user3AdminScope);

        System.out.println("Scopes and Users created successfully.");


    }

    private UserEntity getUserEntity(String name, String userName, String email){
        UserEntity user3 = new UserEntity();
        user3.setName(name);
        user3.setUsername(userName);
        user3.setPassword(passwordEncoder.encode("12345"));
        user3.setEmail(email);

        return user3;
    }
}
