package com.hoanght.repository;

import com.hoanght.entity.Person;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<Person, Long> {
    Optional<Person> findByUsername(String username);

    boolean existsByUsername(String username);
}