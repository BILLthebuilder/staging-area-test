// package Rafiki.Bora.Microfinance.services;

// import Rafiki.Bora.Microfinance.config.security.dto.CustomUserDetails;
// import Rafiki.Bora.Microfinance.dao.repository.UserRepository;
// import Rafiki.Bora.Microfinance.model.users.User;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsServiceImpl implements UserDetailsService {
//     @Autowired
//     private UserRepository userRepository;

//     @Override
//     public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
//         User user = userRepository.findByEmail(s).orElseThrow(() -> new UsernameNotFoundException("User not found with email " + s));
//         return new CustomUserDetails(user);
//     }
// }
