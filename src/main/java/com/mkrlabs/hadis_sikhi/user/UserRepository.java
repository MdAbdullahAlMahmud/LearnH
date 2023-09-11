package com.mkrlabs.hadis_sikhi.user;

import com.mkrlabs.hadis_sikhi.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User> findByEmail(String email);
}
