package com.alibou.book.security;

import com.alibou.book.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Implementation of Spring Security's UserDetailsService interface.
 * 
 * <p>This class is responsible for loading user-specific data during the authentication process.
 * It is automatically called by Spring Security's authentication provider when a user attempts to log in.</p>
 * 
 * <p>Usage:
 * <ul>
 *   <li>Called during authentication flow when validating user credentials</li>
 *   <li>Retrieves user information from the database based on the provided username (email in this case)</li>
 *   <li>Returns a UserDetails object that Spring Security uses for authentication and authorization</li>
 * </ul>
 * </p>
 * 
 * <p>Note: The @Service annotation is commented out, suggesting this implementation might be replaced
 * by another authentication mechanism in the current configuration (possibly JWT or Keycloak as mentioned
 * in the project documentation).</p>
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository repository;
    /**
     * Loads a user by their username (email in this application).
     * 
     * <p>This method is automatically called by Spring Security during the authentication process
     * when a user attempts to log in. It retrieves the user entity from the database and returns
     * it as a UserDetails object.</p>
     * 
     * @param username The username (email) of the user attempting to authenticate
     * @return UserDetails object containing the user's credentials and authorities
     * @throws UsernameNotFoundException if no user is found with the provided email
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
