package com.example.identityservice.service;

import com.example.identityservice.dto.LoginResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.User;
import com.example.identityservice.exception.TokenRefreshException;
import com.example.identityservice.repository.UserRepository;
import com.example.identityservice.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService blacklistService;

    public LoginResponse login(String username, String rawPassword) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        String accessToken = jwtUtils.generateAccessToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());

        return new LoginResponse(accessToken, refreshToken.getToken());
    }

    @Transactional
    public LoginResponse refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB bằng chuỗi requestToken
        RefreshToken oldToken = refreshTokenService.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found"));

        // 2. Hết hạn (expiryDate < now) -> verifyExpiration xóa + ném Exception
        refreshTokenService.verifyExpiration(oldToken);

        // 3. ROTATION: xóa bản ghi Refresh Token cũ khỏi DB (chỉ dùng được 1 lần)
        User user = oldToken.getUser();
        refreshTokenService.delete(oldToken);

        // 4. Tạo Access Token mới cho User từ token cũ
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // 5. Tạo Refresh Token hoàn toàn mới
        RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

        // 6. Trả về cặp Token mới
        return new LoginResponse(newAccessToken, newRefreshToken.getToken());
    }

    public void logout(String token) {
        // 1. Giải mã token để lấy claim "jti" và "exp"
        String jti = jwtUtils.getJtiFromToken(token);
        Date expiration = jwtUtils.getExpirationFromToken(token);

        // 2. TTL = exp - now (giây)
        long ttlSeconds = (expiration.getTime() - System.currentTimeMillis()) / 1000;
        if (ttlSeconds <= 0) {
            throw new TokenRefreshException("Token already expired");
        }

        // 3+4. Lưu blacklist:{jti} = "revoked" với TTL đúng bằng thời gian còn lại của token
        blacklistService.blacklist(jti, ttlSeconds);

        // 5. Xóa luôn Refresh Token trong PostgreSQL để phiên đăng nhập hết hiệu lực hoàn toàn
        String username = jwtUtils.getUsernameFromToken(token);
        userRepository.findByUsername(username).ifPresent(refreshTokenService::deleteByUser);
    }
}
