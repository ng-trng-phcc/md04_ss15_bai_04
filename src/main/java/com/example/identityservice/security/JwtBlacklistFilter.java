package com.example.identityservice.security;

import com.example.identityservice.service.TokenBlacklistService;
import com.example.identityservice.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Chặn Access Token đã logout (jti nằm trong Redis blacklist).
 * Chỉ tác động khi request kèm Bearer token parse được; còn lại cho qua.
 */
@Component
@RequiredArgsConstructor
public class JwtBlacklistFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final TokenBlacklistService blacklistService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            try {
                String jti = jwtUtils.getJtiFromToken(header.substring(7));
                if (blacklistService.isBlacklisted(jti)) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("text/plain;charset=UTF-8");
                    response.getWriter().write("Token revoked (logged out)");
                    return;
                }
            } catch (Exception ex) {
                // Token sai chữ ký/hết hạn/không parse được -> cho qua,
                // endpoint tự xử lý 401/403.
            }
        }
        filterChain.doFilter(request, response);
    }
}
