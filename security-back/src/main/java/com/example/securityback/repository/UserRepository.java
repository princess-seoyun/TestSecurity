package com.example.securityback.repository;

import com.example.securityback.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> { // 레포지토리의 해당 엔티디를 넣어주고, 유저 엔티디의 레포런스 타입을 넣어줌

    Boolean existsByUsername(String username); // existsBy => 존재하는지 확인하는 쿼리절, 즉 usrname 기반으로 존재 유무 확인

    UserEntity findByUsername(String username); // username을 받아 DB 테이블에서 회원을 조회하는 메소드 작성

}
