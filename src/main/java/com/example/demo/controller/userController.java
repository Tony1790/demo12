package com.example.demo.controller;

import com.example.demo.domain.LoginVo;
import com.example.demo.domain.UserVo;
import com.example.demo.domain.response.BaseResponse;
import com.example.demo.domain.response.SingleDataResponse;
import com.example.demo.exception.DuplicatedUsernameException;
import com.example.demo.exception.LoginFailedException;
import com.example.demo.exception.UserNotFoundException;
import com.example.demo.service.ResponseService;
import com.example.demo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class userController {

    private final UserService userService;
    private final ResponseService responseService;
    private final Logger logger = LoggerFactory.getLogger(userController.class);

    @GetMapping("/join")
    public String join() {
        return "hello";
    }

    @PostMapping("/join")
    public ResponseEntity join(@RequestBody UserVo userVo) {
        ResponseEntity responseEntity = null;

        try {
            userVo.setIsEnabled(true);
            userVo.setIsAccountNonExpired(true);
            userVo.setIsAccountNonLocked(true);
            userVo.setIsCredentialsNonExpired(true);

            UserVo savedUser = userService.join(userVo);
            SingleDataResponse<UserVo> response = responseService.getSingleDataResponse(true, "회원 가입 성공", savedUser);

            responseEntity = ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (DuplicatedUsernameException exception) {
            logger.debug(exception.getMessage());
            BaseResponse response = responseService.getBaseResponse(false, exception.getMessage());

            responseEntity = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        return responseEntity;
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginVo loginVo) {
        ResponseEntity responseEntity = null;

        try {
            String token = userService.login(loginVo);

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("Authorization", "Bearer " + token);

            SingleDataResponse<String> response = responseService.getSingleDataResponse(true, "로그인 성공!", token);

            responseEntity = ResponseEntity.status(HttpStatus.OK).headers(httpHeaders).body(response);
        } catch (LoginFailedException exception) {
            logger.debug(exception.getMessage());
            BaseResponse response = responseService.getBaseResponse(false, exception.getMessage());

            responseEntity = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        return responseEntity;
    }

    @GetMapping("/users")
    public ResponseEntity findUserByUsername(final Authentication authentication) {
        ResponseEntity responseEntity = null;

        try {
            int userId = ((UserVo) authentication.getPrincipal()).getU_id();
            UserVo findUser = userService.findByUserId(userId);

            SingleDataResponse<UserVo> response = responseService.getSingleDataResponse(true, "조회에 성공했습니다.", findUser);

            responseEntity = ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (UserNotFoundException exception) {
            logger.debug(exception.getMessage());
            BaseResponse response = responseService.getBaseResponse(false, exception.getMessage());

            responseEntity = ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        return responseEntity;
    }
}
