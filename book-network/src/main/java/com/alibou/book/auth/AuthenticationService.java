package com.alibou.book.auth;

import com.alibou.book.email.EmailService;
import com.alibou.book.email.EmailTemplateName;
import com.alibou.book.role.RoleRepository;
import com.alibou.book.security.JwtService;
import com.alibou.book.user.Token;
import com.alibou.book.user.TokenRepository;
import com.alibou.book.user.User;
import com.alibou.book.user.UserRepository;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

/**
 * Service responsible for handling user authentication operations including
 * registration, login, and account activation via email verification.
 *
 * Core Functionality:
 *
 * Registration (register):
 * Creates a new user with encoded password and USER role
 * Sets account as not enabled initially
 * Sends validation email with activation token
 *
 * Authentication (authenticate):
 * Validates user credentials using Spring's AuthenticationManager
 * Creates JWT token with custom claims (fullName)
 * Returns token in AuthenticationResponse
 *
 * Account Activation (activateAccount):
 * Validates the activation token
 * Checks if token has expired (resends if expired)
 * Enable the user account
 * Updates token with validation timestamp
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    // Repository for user data access
    private final UserRepository userRepository;

//    Encoder for securing user passwords
    private final PasswordEncoder passwordEncoder;
    
//    Service for JWT token operations
    private final JwtService jwtService;
    
//    Spring Security authentication manager
    private final AuthenticationManager authenticationManager;
    
//    Repository for role data access
    private final RoleRepository roleRepository;
    
//    Service for sending emails
    private final EmailService emailService;
    
//    Repository for token data access
    private final TokenRepository tokenRepository;

//    Frontend URL (Angular App) for account activation
    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    /*
     * Registers a new user with the system and sends a validation emai
     * @param request Registration details including name, email, and password
     * @throws MessagingException If there's an error sending the validation email
     */
    public void register(RegistrationRequest request) throws MessagingException {
        var userRole = roleRepository.findByName("USER")
                // todo - better exception handling
                .orElseThrow(() -> new IllegalStateException("ROLE USER was not initiated"));
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .accountLocked(false)
                .enabled(false)
                .roles(List.of(userRole))
                .build();
        userRepository.save(user);
        sendValidationEmail(user);
    }

    /*
     * Authenticates a user and generates a JWT token
     * 
     * @param request Authentication credentials (email and password)
     * @return AuthenticationResponse containing the JWT token
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // This code authenticates a user by:
        // 1. Using Spring Security's AuthenticationManager to verify credentials
        // 2. Creating an authentication token with the user's email and password
        // 3. If authentication succeeds, returns the authenticated user details
        // 4. If authentication fails, throws an AuthenticationException
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var claims = new HashMap<String, Object>();
        var user = ((User) auth.getPrincipal());
        claims.put("fullName", user.getFullName());

        var jwtToken = jwtService.generateToken(claims, (User) auth.getPrincipal());
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    /*
     * Activates a user account using the provided token
     * If the token is expired, sends a new validation email
     * 
     * @param token The activation token sent to the user's email
     * @throws MessagingException If there's an error sending a new validation email
     */
    @Transactional
    public void activateAccount(String token) throws MessagingException {
        Token savedToken = tokenRepository.findByToken(token)
                // todo exception has to be defined
                .orElseThrow(() -> new RuntimeException("Invalid token"));
        if (LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
            sendValidationEmail(savedToken.getUser());
            throw new RuntimeException("Activation token has expired. A new token has been send to the same email address");
        }

        var user = userRepository.findById(savedToken.getUser().getId())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        user.setEnabled(true);
        userRepository.save(user);

        savedToken.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(savedToken);
    }

    /*
     * Generates a new activation token for a user and saves it to the database
     * 
     * @param user The user for whom to generate the token
     * @return The generated token string
     */
    private String generateAndSaveActivationToken(User user) {
        // Generate a token
        String generatedToken = generateActivationCode(6);
        var token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .user(user)
                .build();
        tokenRepository.save(token);

        return generatedToken;
    }

    /*
     * Sends an account activation email to the user
     * 
     * @param user The user to whom the email will be sent
     * @throws MessagingException If there's an error sending the email
     */
    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user);

        emailService.sendEmail(
                user.getEmail(),
                user.getFullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                newToken,
                "Account activation"
                );
    }

    /*
     * Generates a secure random numeric activation code of specified length
     * 
     * @param length The length of the activation code
     * @return The generated activation code
    */
    private String generateActivationCode(int length) {
        String characters = "0123456789";
        StringBuilder codeBuilder = new StringBuilder();

        SecureRandom secureRandom = new SecureRandom();

        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }

        return codeBuilder.toString();
    }
}
