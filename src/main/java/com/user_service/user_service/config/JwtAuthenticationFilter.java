package com.user_service.user_service.config;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String requestUri = request.getRequestURI();
        log.info("JwtFilter: Procesando request para '{}'", requestUri);

        final String authHeader = request.getHeader(AUTH_HEADER);
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            log.info("JwtFilter: No se encontró Header 'Authorization Bearer' para '{}'. Continuando cadena.", requestUri);
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(BEARER_PREFIX.length());
        log.debug("JwtFilter: Token extraído: {}", jwt);

        try {
            userEmail = jwtUtils.extractUsername(jwt);
            log.info("JwtFilter: Email extraído '{}' para '{}'", userEmail, requestUri);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                log.info("JwtFilter: Cargando UserDetails para '{}'", userEmail);
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                log.info("JwtFilter: UserDetails cargados para '{}': Authorities={}", userEmail, userDetails.getAuthorities());

                log.info("JwtFilter: Validando token para '{}'", userEmail);
                if (jwtUtils.validateToken(jwt, userDetails.getUsername())) {
                    log.info("JwtFilter: Token VÁLIDO para '{}'. Estableciendo Authentication.", userEmail);
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("JwtFilter: Authentication establecida en SecurityContext para '{}'", userEmail);
                } else {
                    log.warn("JwtFilter: Token INVÁLIDO para usuario '{}' en request '{}'", userEmail, requestUri);
                }
            } else {
                log.info("JwtFilter: Email nulo o ya existe Authentication en SecurityContext para '{}'", requestUri);
            }
        } catch (ExpiredJwtException e) {
            log.warn("JwtFilter: Token expirado para request '{}': {}", requestUri, e.getMessage());
            SecurityContextHolder.clearContext();
        } catch (JwtException e) {
            log.error("JwtFilter: Error JWT para request '{}': {}", requestUri, e.getMessage());
            SecurityContextHolder.clearContext();
        } catch (Exception e) {
            log.error("JwtFilter: Error inesperado para request '{}': {}", requestUri, e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }

        log.info("JwtFilter: Continuando cadena de filtros para '{}'", requestUri);
        filterChain.doFilter(request, response);
    }
}