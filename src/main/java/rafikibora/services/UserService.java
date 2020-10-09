package rafikibora.services;

// import rafikibora.config.security.dto.LoginRequest;
// import rafikibora.config.security.dto.LoginResponse;
import rafikibora.security.dto.UserDto;
//import rafikibora.config.security.dto.UserSummary;
import rafikibora.model.users.User;
import org.springframework.http.ResponseEntity;

public interface UserService {
    //ResponseEntity<LoginResponse> login(LoginRequest loginRequest, String accessToken, String refreshToken);

    //ResponseEntity<LoginResponse> refresh(String accessToken, String refreshToken);

    void save(UserDto user);


    //UserSummary getUserProfile();
}
