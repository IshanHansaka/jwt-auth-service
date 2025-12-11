package com.ishan.security.jwt_auth_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ishan.security.jwt_auth_service.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

}
