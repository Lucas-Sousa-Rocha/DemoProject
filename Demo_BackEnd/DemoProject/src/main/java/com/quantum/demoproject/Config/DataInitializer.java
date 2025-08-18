package com.quantum.demoproject.Config;

import com.quantum.demoproject.model.RoleEntity;
import com.quantum.demoproject.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepo;

    public DataInitializer(RoleRepository roleRepo) {
        this.roleRepo = roleRepo;
    }

    @Override
    public void run(String... args) throws Exception {
        if (roleRepo.findByName("ROLE_ADMIN").isEmpty()) {
            RoleEntity admin = new RoleEntity();
            admin.setName("ROLE_ADMIN");
            roleRepo.save(admin);
        }

        if (roleRepo.findByName("ROLE_USER").isEmpty()) {
            RoleEntity user = new RoleEntity();
            user.setName("ROLE_USER");
            roleRepo.save(user);
        }

        System.out.println("Roles iniciais criadas com sucesso!");
    }
}
