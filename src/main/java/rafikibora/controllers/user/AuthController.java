// package Rafiki.Bora.Microfinance.controllers.user;

// import Rafiki.Bora.Microfinance.config.security.dto.LoginRequest;
// import Rafiki.Bora.Microfinance.config.security.dto.LoginResponse;
// import Rafiki.Bora.Microfinance.config.security.util.SecurityCipher;
// import Rafiki.Bora.Microfinance.services.UserService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.MediaType;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.web.bind.annotation.*;

// import javax.validation.Valid;


// @RestController
// @RequestMapping("/auth")
// public class AuthController {
//     @Autowired
//     private AuthenticationManager authenticationManager;

//     @Autowired
//     private UserService userService;

//     @PostMapping(value = "/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
//     public ResponseEntity<LoginResponse> login(
//             @CookieValue(name = "accessToken", required = false) String accessToken,
//             @CookieValue(name = "refreshToken", required = false) String refreshToken,
//             @Valid @RequestBody LoginRequest loginRequest
//     ) {
//         Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
//         SecurityContextHolder.getContext().setAuthentication(authentication);

//         String decryptedAccessToken = SecurityCipher.decrypt(accessToken);
//         String decryptedRefreshToken = SecurityCipher.decrypt(refreshToken);
//         return userService.login(loginRequest, decryptedAccessToken, decryptedRefreshToken);
//     }

//     @PostMapping(value = "/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
//     public ResponseEntity<LoginResponse> refreshToken(@CookieValue(name = "accessToken", required = false) String accessToken,
//                                                       @CookieValue(name = "refreshToken", required = false) String refreshToken) {
//         String decryptedAccessToken = SecurityCipher.decrypt(accessToken);
//         String decryptedRefreshToken = SecurityCipher.decrypt(refreshToken);
//         return userService.refresh(decryptedAccessToken, decryptedRefreshToken);
//     }
// }
