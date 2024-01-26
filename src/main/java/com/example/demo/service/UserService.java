package com.example.demo.service;

import com.example.demo.domain.LoginVo;
import com.example.demo.domain.UserVo;
import com.example.demo.exception.DuplicatedUsernameException;
import com.example.demo.exception.LoginFailedException;
import com.example.demo.mapper.UserMapper;
import com.example.demo.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserVo join(UserVo userVo) {
        if (userMapper.findUserByUsername(userVo.getU_username()).isPresent()) {
            throw new DuplicatedUsernameException("이미 가입된 유저입니다");
        }

        userVo.setU_password(passwordEncoder.encode(userVo.getPassword()));
        userMapper.save(userVo);

        return userMapper.findUserByUsername(userVo.getU_username()).get();
    }

    public String login(LoginVo loginVo) {
        UserVo userVo = userMapper.findUserByUsername(loginVo.getUsername())
                .orElseThrow(()-> new LoginFailedException("잘못된 아이디 입니다."));

        if(!passwordEncoder.matches(loginVo.getPassword(), userVo.getPassword())) {
            throw new LoginFailedException("비밀번호가 틀렸습니다.");
        }

        return jwtTokenProvider.createToken(userVo.getU_id(), userVo.getU_Role());
    }

    public UserVo findByUserId(int userId) {
        return userMapper.findByUserId(userId).orElseThrow(() -> new UsernameNotFoundException("없는 유저입니다."));
    }

}
