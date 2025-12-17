package com.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType.H2;


@EnableWebSecurity // Active la sécurité web de Spring Security
@Configuration // Indique que cette classe est une classe de configuration Spring
public class WebSecurityConfig {

    @Bean // Déclare ce bean dans le contexte Spring
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http // Configuration des règles de sécurité HTTP

                // Configuration CSRF (Cross-Site Request Forgery)
                // Désactivé pour la console H2 afin d'éviter les erreurs
                .csrf((csrf) -> csrf
                        .ignoringRequestMatchers("/h2-console/**")
                ).headers((headers) -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable)
                )

                // Configuration des autorisations pour les requêtes HTTP
                .authorizeHttpRequests((requests)-> requests
                        // Autorise l'accès public aux chemins "/" et "/home"
                        .requestMatchers("/", "/home", "/h2-console/**").permitAll()
                        // Toutes les autres requêtes nécessitent une authentification
                        .anyRequest().authenticated()
                )
                // Configuration de la page de login personnalisée
                .formLogin((form)-> form
                        // Spécifie l'URL de la page de connexion personnalisée
                        .loginPage("/login")

                        // Autorise l'accès public à la fonctionnalité de déconnexion
                        .permitAll()
                )

                // Configuration de la déconnexion
                // Autorise tout le monde à se déconnecter
                .logout(LogoutConfigurer::permitAll);

        // Construction et retour de la chaîne de filtres de sécurité
        return http.build();
    }



    /**
     * Bean permettant de chiffrer les mots de passe
     * BCrypt est recommandé par Spring Security
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Définition des utilisateurs en mémoire (InMemory)
     * Utile uniquement pour les tests / démos
     */
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource) {
        UserDetails user = User.builder()
                .username("eva@email.com") // nom d'utilisateur
                .password(passwordEncoder().encode("password")) // mot de passe
                .roles("USER") // rôle USER
                .build();

        // Utilisateur administrateur
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("password"))
                .roles("USER", "ADMIN") // rôles USER et ADMIN
                .build();

        UserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.createUser (admin);
        users.createUser(user);

        return users;
    }

        // Gestionnaire d'utilisateurs en mémoire
       // return new InMemoryUserDetailsManager(user, admin);



    /**
     * Configuration de la base de données H2 embarquée
     * Utilisée par Spring Security pour stocker les utilisateurs
     */
    //dataSource
    @Bean
    DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(H2) // Type de base : H2 (en mémoire)
                // Script SQL par défaut de Spring Security
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .setName("testdb") // Nom de la base
                .build();
    }
}
//    public class MyUserDetails implements UserDetailsService {
//        private String username;
//        private String password;
//
//        @Override
//        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//            return null;
//        }






