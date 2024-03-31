package com.kk.controller;

import com.kk.config.JwtProvider;
import com.kk.exception.UserException;
import com.kk.modal.User;
import com.kk.repository.UserRepository;
import com.kk.request.LoginRequest;
import com.kk.response.AuthResponse;
import com.kk.service.CustomUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private CustomUserServiceImpl customUserService;

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> createUserHandler(@RequestBody User user) throws UserException {

        String email=user.getEmail();
        String password=user.getPassword();
        String firstName=user.getFirstName();
        String lastName=user.getLastName();
        String mobile=user.getMobile();

        User user1=userRepository.findByEmail(email);

        if(user1!=null){
            throw new UserException("Email is already used for another account.");
        }

        User createdUser=new User();
        createdUser.setEmail(email);
        createdUser.setPassword(passwordEncoder.encode(password));
        createdUser.setFirstName(firstName);
        createdUser.setLastName(lastName);
        createdUser.setMobile(mobile);

        User savedUser=userRepository.save(createdUser);

        Authentication authentication=new UsernamePasswordAuthenticationToken(savedUser.getEmail(),savedUser.getPassword());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token=jwtProvider.generateToken(authentication);

        AuthResponse authResponse=new AuthResponse(token , "Signup success");

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.CREATED);

    }

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> loginUserHandler(@RequestBody LoginRequest loginRequest){

        String username=loginRequest.getEmail();
        String password=loginRequest.getPassword();

        Authentication authentication=authenticate(username,password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token=jwtProvider.generateToken(authentication);

        AuthResponse authResponse=new AuthResponse();
        authResponse.setJwt(token);
        authResponse.setMessage("Signin success");

        return new ResponseEntity<AuthResponse>(authResponse, HttpStatus.CREATED);
    }

    private Authentication authenticate(String username, String password) {
        UserDetails userDetails= customUserService.loadUserByUsername(username);
        if(userDetails==null){
            throw new BadCredentialsException("Invalid username");
        }

        if(!passwordEncoder.matches(password,userDetails.getPassword())){
            throw new BadCredentialsException("Invalid password...");
        }


        return new UsernamePasswordAuthenticationToken(userDetails ,null,userDetails.getAuthorities());
    }
}
