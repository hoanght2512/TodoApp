package com.hoanght.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hoanght.common.RoleName;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "roles")
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_name", unique = true)
    @Enumerated(EnumType.STRING)
    private RoleName name;

    @JsonIgnore
    @ManyToMany(mappedBy = "roles", cascade = CascadeType.MERGE)
    private List<User> people;

    @Override
    public String getAuthority() {
        return name.toString();
    }

    public Role(RoleName roleName) {
        this.name = roleName;
    }
}
