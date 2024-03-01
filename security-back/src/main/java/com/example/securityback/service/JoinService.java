package com.example.securityback.service;

import com.example.securityback.dto.JoinDTO;
import com.example.securityback.entity.UserEntity;
import com.example.securityback.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if(isExist) {
            return; // isExist 에 true 가 반환되는 것이라면 이미 사용자가 존재해서 return 을 반환, 즉 존재하면 회원가입 안 되도록 함
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); // 암호화를 진행한 후 비밀번호를 넣도록
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
