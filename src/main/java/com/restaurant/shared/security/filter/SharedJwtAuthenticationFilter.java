package com.restaurant.shared.security.filter;

import com.restaurant.shared.security.context.TenantContext;
import com.restaurant.shared.security.service.SharedJwtService;
import com.restaurant.shared.security.spi.SecurityIntegrationProvider;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@Component
@AllArgsConstructor
public class SharedJwtAuthenticationFilter extends OncePerRequestFilter {

    private final SharedJwtService jwtService;
    private final SecurityIntegrationProvider securityProvider;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Resolve Tenant from Domain
        String domain = extractDomain(request);
        if (domain != null) {
            Optional<Long> tenantIdOpt = securityProvider.resolveTenantIdByDomain(domain);
            if (tenantIdOpt.isPresent()) {
                Object id = tenantIdOpt.get();
                if (id instanceof Number n) {
                    TenantContext.setCurrentTenant(n.longValue());
                }
            }
        }

        // 2. Fallback: X-Tenant-ID
        if (TenantContext.getCurrentTenant() == null) {
            String tenantHeader = request.getHeader("X-Tenant-ID");
            if (StringUtils.hasText(tenantHeader)) {
                try {
                    TenantContext.setCurrentTenant(Long.parseLong(tenantHeader));
                } catch (NumberFormatException e) {
                    log.warn("Invalid Tenant ID in header: {}", tenantHeader);
                }
            }
        }

        try {
            String jwt = extractJwt(request);

            if (jwt != null) {
                // Extract companyId from Token if available
                try {
                    var claims = jwtService.extractAllClaims(jwt);
                    Object scope = claims.get("scope");
                    Object companyIdClaim = claims.get("companyId");

                    if ("platform".equals(scope)) {
                        if (companyIdClaim != null) {
                            log.error("Security Breach Attempt: Platform token with companyId {} detected!",
                                    companyIdClaim);
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid token scope");
                            return;
                        }
                        TenantContext.clear(); // Ensure no tenant for platform scope
                    } else if (companyIdClaim instanceof Number n) {
                        TenantContext.setCurrentTenant(n.longValue());
                    }
                } catch (Exception e) {
                    log.debug("Could not extract claims from token", e);
                }

                String username = jwtService.extractUsername(jwt);
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = securityProvider.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            log.warn("JWT Expired: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"code\": 401, \"message\": \"Token expired. Please login again.\"}");
        } catch (Exception e) {
            log.error("Authentication failed: ", e);
            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private String extractJwt(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return request.getParameter("token");
    }

    private String extractDomain(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (StringUtils.hasText(origin)) {
            return origin.replace("https://", "").replace("http://", "").split(":")[0].toLowerCase();
        }
        String host = request.getHeader("Host");
        if (StringUtils.hasText(host)) {
            return host.split(":")[0].toLowerCase();
        }
        return null;
    }
}
