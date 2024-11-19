package net.dreamsicle.webfluxsecurity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Component
public class PBFDK2Encoder implements PasswordEncoder {

    private static final String SECRET_KEY_INSTANCE = "PBKDF2WithHmacSHA512";
    @Value("${security.secret}")
    private Integer secret;
    @Value("${security.iterations}")
    private Integer iterations;
    @Value("${security.keyLength}")
    private Integer keyLength;

    @Override
    public String encode(CharSequence rawPassword) {

        try {
            byte [] secretKey = SecretKeyFactory.getInstance(SECRET_KEY_INSTANCE)
                  .generateSecret(new PBEKeySpec(
                        rawPassword.toString().toCharArray(),
                        secret.toString().getBytes(),
                        iterations,
                        keyLength)
                  ).getEncoded();
            return Base64.getEncoder().encodeToString(secretKey);

        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }
}
