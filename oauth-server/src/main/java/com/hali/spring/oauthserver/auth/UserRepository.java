package com.hali.spring.oauthserver.auth;

import org.springframework.data.repository.ListCrudRepository;

public interface UserRepository  extends ListCrudRepository<UserEntity,String> {
    UserEntity findByUsername(String username);
}
