package com.example.demo.mapper;

import com.example.demo.domain.UserVo;
import org.apache.ibatis.annotations.Mapper;

import java.util.Optional;

@Mapper
public interface UserMapper {
    Optional<UserVo> findUserByUsername(String u_username);
    Optional<UserVo> findByUserId(int userId);
    void save(UserVo userVo);
}
