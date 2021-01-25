package com.example.register.registration;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;
import java.util.regex.Pattern;

@Service
public class EmailValidator implements Predicate<String> {

    private static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[a-zA-Z0-9._%+ -\"]+@[a-zA-Z]+\\.[a-zA-Z]{2,3}$", Pattern.CASE_INSENSITIVE);

    @Override
    public boolean test(String email) {

        if(!VALID_EMAIL_ADDRESS_REGEX.matcher(email).matches()){
            throw new IllegalStateException("Email is not valid");
        }
        return true;
    }
}
