package com.example.demo.service;

import com.example.demo.domain.UserVo;
import com.example.demo.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class MyUserDetailsService implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userMapper.findByUserId(Integer.valueOf(username))
                .map(user -> addAuthorities(user))
                .orElseThrow(()->new UsernameNotFoundException(username + "> 찾을 수 없습니다."));
    }

    private UserVo addAuthorities(UserVo userVo) {
        userVo.setAuthorities(Collections.singleton(new SimpleGrantedAuthority(userVo.getU_Role())));
        return userVo;
    }

}
