package com.quantum.demoproject.DTO;

import java.util.List;

public class MeView {


        private Long id;
        private String email;
        private String username;
        private String name;
        private List<String> roles;

        public MeView(Long id, String email, String username, String name, List<String> roles) {
            this.id = id;
            this.email = email;
            this.username = username;
            this.name = name;
            this.roles = roles;
        }

        public Long getId() { return id; }
        public String getEmail() { return email; }
        public String getUsername() { return username; }
        public String getName() { return name; }
        public List<String> getRoles() { return roles; }

}
