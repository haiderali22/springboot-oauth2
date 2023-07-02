package com.hali.spring.oauthserver.auth;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Entity
@Setter
@Getter
@NoArgsConstructor
public class UserScope {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private UserEntity user;

    @ManyToOne
    @JoinColumn(name = "scope_id")
    private ScopeEntity scope;

    public UserScope(UserEntity user, ScopeEntity scope) {
        this.user = user;
        this.scope = scope;
    }
}
