package com.zuehlke.bgre.security.repository;

import com.zuehlke.bgre.security.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
