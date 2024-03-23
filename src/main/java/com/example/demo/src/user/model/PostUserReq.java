package com.example.demo.src.user.model;

import com.example.demo.src.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PostUserReq {

    private String email;
    private String password;
    private String name;
    private boolean isOAuth;

    public User toEntity() {
        return User.builder()
                .email(this.email)
                .password(this.password)
                .name(this.name)
                .isOAuth(this.isOAuth)
                .build();
    }
}
