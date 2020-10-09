package rafikibora.services;

import rafikibora.security.dto.*;
// import rafikibora.config.security.util.CookieUtil;
import rafikibora.dao.repository.UserRepository;
import rafikibora.model.users.Roles;
import rafikibora.model.users.User;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@Slf4j
//@AllArgsConstructor
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;

    // @Autowired
    // private TokenProvider tokenProvider;

    // @Autowired
    // private CookieUtil cookieUtil;

    private BCryptPasswordEncoder bCryptPasswordEncoder;


    @Transactional
    public void save(UserDto user){
        User newUser = new User();
            newUser.setFirstName(user.getFirstName());
            newUser.setLastName(user.getLastName());
            newUser.setEmail(user.getEmail());
            newUser.setPhoneNo(user.getPhoneNo());
            newUser.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
            log.info("***********************");
            log.info("The Data here is:", user);
            log.info("***********************");
        userRepository.save(newUser);
    }

    public User createUser(User user) {

        final String encryptedPassword = bCryptPasswordEncoder.encode(user.getPassword());

        user.setPassword(encryptedPassword);

         User createdUser = userRepository.save(user);

        return createdUser;
    }

    // @Override
    // public ResponseEntity<LoginResponse> login(LoginRequest loginRequest, String accessToken, String refreshToken) {
    //     String email = loginRequest.getEmail();
    //     User user = userRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("User not found with email " + email));

    //     Boolean accessTokenValid = tokenProvider.validateToken(accessToken);
    //     Boolean refreshTokenValid = tokenProvider.validateToken(refreshToken);

    //     HttpHeaders responseHeaders = new HttpHeaders();
    //     Token newAccessToken;
    //     Token newRefreshToken;
    //     if (!accessTokenValid && !refreshTokenValid) {
    //         newAccessToken = tokenProvider.generateAccessToken(user.getFirstName());
    //         newRefreshToken = tokenProvider.generateRefreshToken(user.getFirstName());
    //         addAccessTokenCookie(responseHeaders, newAccessToken);
    //         addRefreshTokenCookie(responseHeaders, newRefreshToken);
    //     }

    //     if (!accessTokenValid && refreshTokenValid) {
    //         newAccessToken = tokenProvider.generateAccessToken(user.getFirstName());
    //         addAccessTokenCookie(responseHeaders, newAccessToken);
    //     }

    //     if (accessTokenValid && refreshTokenValid) {
    //         newAccessToken = tokenProvider.generateAccessToken(user.getFirstName());
    //         newRefreshToken = tokenProvider.generateRefreshToken(user.getFirstName());
    //         addAccessTokenCookie(responseHeaders, newAccessToken);
    //         addRefreshTokenCookie(responseHeaders, newRefreshToken);
    //     }

    //     LoginResponse loginResponse = new LoginResponse(LoginResponse.SuccessFailure.SUCCESS, "Auth successful. Tokens are created in cookie.");
    //     return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);

    // }

    // @Override
    // public ResponseEntity<LoginResponse> refresh(String accessToken, String refreshToken) {
    //     Boolean refreshTokenValid = tokenProvider.validateToken(refreshToken);
    //     if (!refreshTokenValid) {
    //         throw new IllegalArgumentException("Refresh Token is invalid!");
    //     }

    //     String currentUserEmail = tokenProvider.getUsernameFromToken(accessToken);

    //     Token newAccessToken = tokenProvider.generateAccessToken(currentUserEmail);
    //     HttpHeaders responseHeaders = new HttpHeaders();
    //     responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(newAccessToken.getTokenValue(), newAccessToken.getDuration()).toString());

    //     LoginResponse loginResponse = new LoginResponse(LoginResponse.SuccessFailure.SUCCESS, "Auth successful. Tokens are created in cookie.");
    //     return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
    // }

    // @Override
    // public UserSummary getUserProfile() {
    //     Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    //     CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

    //     User user = userRepository.findByEmail(customUserDetails.getUsername()).orElseThrow(() -> new IllegalArgumentException("User not found with email " + customUserDetails.getUsername()));
    //     return user.toUserSummary();
    // }

    // private void addAccessTokenCookie(HttpHeaders httpHeaders, Token token) {
    //     httpHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(token.getTokenValue(), token.getDuration()).toString());
    // }

    // private void addRefreshTokenCookie(HttpHeaders httpHeaders, Token token) {
    //     httpHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.createRefreshTokenCookie(token.getTokenValue(), token.getDuration()).toString());
    // }
}
