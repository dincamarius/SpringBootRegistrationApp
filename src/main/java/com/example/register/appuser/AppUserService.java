package com.example.register.appuser;

import com.example.register.registration.token.ConfirmationToken;
import com.example.register.registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "User with email %s not found";
    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final ConfirmationTokenService confirmationTokenService;


    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email).orElseThrow(()->
                new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG,email)));
    }

    public String singUpUserAndReturnToken(AppUser appUser){

        // if user exist, check is newUser is same as OldUser
        if(appUserRepository.findByEmail(appUser.getEmail()).isPresent()){

            AppUser oldUser = appUserRepository.findByEmail(appUser.getEmail()).get();
            Set<ConfirmationToken> oldNonExpiredConfirmationTokens = oldUser.getConfirmationTokens()
                    .stream()
                    .filter(oldToken -> LocalDateTime.now().isBefore(oldToken.getExpiresAt()) )
                    .collect(Collectors.toSet());

            //ConfirmationToken oldConfirmationToken = confirmationTokenService.getByAppUser(appUser).get();
            // if newUser==oldUser, check if accountConfirmed
            if (compareUsers(appUser,oldUser)) {

                boolean accountConfirmed = oldUser.getEnabled();
                //boolean tokenExpired = LocalDateTime.now().isAfter(oneOldUnexpiredToken.getExpiresAt());
                if (accountConfirmed) {
                    throw new IllegalStateException("User already exist and account was confirmed");
                } else {
                    // if there are none nonExpiredTokens, generate one and send email
                    if (oldNonExpiredConfirmationTokens.isEmpty()) {
                        String token = UUID.randomUUID().toString();
                        ConfirmationToken confirmationToken = new ConfirmationToken(
                                token,
                                LocalDateTime.now(),
                                LocalDateTime.now().plusMinutes(15),
                                oldUser
                        );
                        confirmationTokenService.saveConfirmationToken(confirmationToken);
                        return token;
                    } else {
                        // if any non expired token is found, resend it
                        return oldNonExpiredConfirmationTokens.stream().findAny().get().getToken();
                    }
                }
            } else {
                // if user with same email does not match, delete it (cascade tokens) and insert new one
//                deleteUserById(oldUser.getId());
//                String encodedPassword = passwordEncoder.encode(appUser.getPassword());
//                appUser.setPassword(encodedPassword);
//                appUserRepository.save(appUser);
//
//                String token = UUID.randomUUID().toString();
//                ConfirmationToken confirmationToken = new ConfirmationToken(
//                        token,
//                        LocalDateTime.now(),
//                        LocalDateTime.now().plusMinutes(15),
//                        appUser
//                );
//                confirmationTokenService.saveConfirmationToken(confirmationToken);
//                return token;
                throw new IllegalStateException(String.format("User with email %s already exist",appUser.getEmail()));

            }

            // if new user, follow happy flow
        } else {
            String encodedPassword = passwordEncoder.encode(appUser.getPassword());
            appUser.setPassword(encodedPassword);
            appUserRepository.save(appUser);

            String token = UUID.randomUUID().toString();
            ConfirmationToken confirmationToken = new ConfirmationToken(
                    token,
                    LocalDateTime.now(),
                    LocalDateTime.now().plusMinutes(15),
                    appUser
            );
            confirmationTokenService.saveConfirmationToken(confirmationToken);
            return token;
        }

    }

    public void enableUser(String email){
       appUserRepository.enableAppUserByEmail(email);
    }

    public void deleteUserById(Long id){
        appUserRepository.deleteUserById(id);
    }

    private boolean compareUsers(AppUser userToBeRegistered, AppUser existingUser){
        if (userToBeRegistered.getFirstName().equals(existingUser.getFirstName())
            && userToBeRegistered.getLastName().equals(existingUser.getLastName())
            && existingUser.getPassword().equals(passwordEncoder.encode(userToBeRegistered.getPassword()))
            && userToBeRegistered.getAppUserRole().equals(existingUser.getAppUserRole())
        ) {
            return true;
        }
        return false;
    }
}
