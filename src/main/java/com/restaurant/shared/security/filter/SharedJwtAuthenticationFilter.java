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
            log.error("Authentication filter error: {}", e.getMessage());
            // If cache fails, we still want the request to proceed if possible.
            // Spring Security filters downstream will handle access denial.
            if (!response.isCommitted()) {
                filterChain.doFilter(request, response);
            }
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
        // 1. Try Origin (Primary for CORS Requests from browsers)
        String origin = request.getHeader("Origin");
        if (StringUtils.hasText(origin)) {
            String domain = cleanDomain(origin);
            if (domain != null) {
                log.info("Extracted domain from Origin: {}", domain);
                return domain;
            }
        }

        // 2. Try Referer (Fallback for Navigation / Direct Links)
        String referer = request.getHeader("Referer");
        if (StringUtils.hasText(referer)) {
            String domain = cleanDomain(referer);
            if (domain != null) {
                log.info("Extracted domain from Referer: {}", domain);
                return domain;
            }
        }

        // 3. Try X-Forwarded-Host (Reverse Proxy / Cloudflare Tunnel)
        String forwardedHost = request.getHeader("X-Forwarded-Host");
        if (StringUtils.hasText(forwardedHost)) {
            String domain = cleanDomain(forwardedHost.split(",")[0]);
            if (domain != null) {
                log.info("Extracted domain from X-Forwarded-Host: {}", domain);
                return domain;
            }
        }

        // 4. Fallback to Host
        String host = request.getHeader("Host");
        if (StringUtils.hasText(host)) {
            String domain = cleanDomain(host);
            log.info("Extracted domain from Host: {}", domain);
            return domain;
        }

        return null;
    }

    private String cleanDomain(String value) {
        if (!StringUtils.hasText(value))
            return null;
        String val = value.strip().replaceAll("\\p{Cf}", "");
        if ("null".equalsIgnoreCase(val))
            return null;

        // Try parsing as URI for Origin/Referer/URLs
        if (val.startsWith("http://") || val.startsWith("https://")) {
            try {
                java.net.URI uri = java.net.URI.create(val);
                String host = uri.getHost();
                if (StringUtils.hasText(host)) {
                    return host.toLowerCase();
                }
            } catch (Exception ignored) {
                // Ignore and fall through to manual parsing
            }
        }

        // Manual parsing fallback (for cases like "example.com:8080" or simple hosts)
        String domain = val.replace("https://", "").replace("http://", "");
        // Remove path if present (for Referer)
        if (domain.contains("/")) {
            domain = domain.split("/")[0];
        }
        // Remove port if present
        if (domain.contains(":")) {
            domain = domain.split(":")[0];
        }
        return domain.toLowerCase().trim();
    }
}
