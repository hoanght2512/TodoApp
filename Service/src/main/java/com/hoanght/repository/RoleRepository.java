package com.hoanght.repository;

import com.hoanght.common.RoleName;
import com.hoanght.entity.Role;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends CrudRepository<Role, Long> {
    Optional<Role> findByName(RoleName name);

    boolean existsByName(RoleName roleName);
}