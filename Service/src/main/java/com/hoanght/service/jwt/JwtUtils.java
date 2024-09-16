package com.hoanght.service.jwt;

import com.hoanght.entity.RefreshToken;
import com.hoanght.repository.RefreshTokenRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
@Log4j2
public class JwtUtils {
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.expiration}")
    private Long accessExpiration;

    public String getToken(HttpServletRequest request) {
        String tokenHeader = request.getHeader("Authorization");
        if (tokenHeader != null && tokenHeader.startsWith("Bearer ")) {
            return tokenHeader.substring(7);
        }
        return null;
    }

    public String generateAccessToken(String username) {
        Date expirationDate = new Date(new Date().getTime() + accessExpiration);
        return Jwts.builder().setSubject(username).setExpiration(expirationDate).setIssuedAt(new Date()).signWith(
                SignatureAlgorithm.HS512, secretKey).compact();
    }

    public String generateRefreshToken(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessExpiration * 2);

        String refreshToken = Jwts.builder().setSubject(username).setIssuedAt(now).setExpiration(expiryDate).signWith(
                SignatureAlgorithm.HS512, secretKey).compact();

        refreshTokenRepository.deleteByUsername(username);

        refreshTokenRepository.save(
                RefreshToken.builder().username(username).token(refreshToken).expiryDate(expiryDate.getTime()).build());

        return refreshToken;
    }

    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @SuppressWarnings("unused")
    // This method for admin to logout user
    public void deleteRefreshTokenByUsername(String username) {
        refreshTokenRepository.deleteByUsername(username);
    }

    public String getUsernameFromToken(String token) {
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
        } catch (Exception ex) {
            log.info("Can not get username from token");
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getExpiration().after(
                    new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public boolean validateRefreshToken(String token) {
        if (validateToken(token)) {
            return refreshTokenRepository.findByToken(token).isPresent();
        }
        return false;
    }
}
