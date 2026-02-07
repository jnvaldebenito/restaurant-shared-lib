package com.restaurant.shared.security.config;

import com.restaurant.shared.security.filter.SharedJwtAuthenticationFilter;
import com.restaurant.shared.security.handler.SharedAccessDeniedHandler;
import com.restaurant.shared.security.handler.SharedAuthenticationEntryPoint;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Log4j2
public class BaseSecurityConfig {

  private final SharedJwtAuthenticationFilter jwtAuthenticationFilter;
  private final SharedAuthenticationEntryPoint authenticationEntryPoint;
  private final SharedAccessDeniedHandler accessDeniedHandler;
  private final Optional<AuthorizationManager<RequestAuthorizationContext>> authorizationManager;

  @Value("${cors.allowed-origins:*}")
  private String allowedOrigins;

  @Bean
  @ConditionalOnMissingBean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable())
        .cors(Customizer.withDefaults())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .authorizeHttpRequests(
            auth -> {
              auth.requestMatchers(
                      "/api/notifications/subscribe",
                      "/public/**",
                      "/auth/**",
                      "/v3/api-docs/**",
                      "/swagger-ui/**")
                  .permitAll();
              if (authorizationManager.isPresent()) {
                auth.anyRequest().access(authorizationManager.get());
              } else {
                auth.anyRequest().authenticated();
              }
            })
        .exceptionHandling(
            ex ->
                ex.authenticationEntryPoint(authenticationEntryPoint)
                    .accessDeniedHandler(accessDeniedHandler))
        .headers(
            headers ->
                headers
                    .frameOptions(frame -> frame.deny())
                    .xssProtection(
                        xss ->
                            xss.headerValue(
                                org.springframework.security.web.header.writers
                                    .XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK))
                    .contentTypeOptions(Customizer.withDefaults())
                    .httpStrictTransportSecurity(
                        hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                    .contentSecurityPolicy(
                        csp ->
                            csp.policyDirectives(
                                "default-src 'self'; "
                                    + "script-src 'self' 'unsafe-inline'; "
                                    + // unsafe-inline needed for some
                                    // SPAs, but should be replaced
                                    // by nonces if possible
                                    "style-src 'self' 'unsafe-inline'; "
                                    + "img-src 'self' data: https:; "
                                    + "connect-src 'self' *.itss.app; "
                                    + "frame-ancestors 'none'; "
                                    + "form-action 'self';")))
        .build();
  }

  @Bean
  @ConditionalOnMissingBean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();

    if (allowedOrigins.equals("*")) {
      log.warn(
          "CORS configured with wildcard origin pattern. This is NOT recommended for production.");
      config.setAllowedOriginPatterns(List.of("*"));
    } else {
      config.setAllowedOrigins(List.of(allowedOrigins.split(",")));
    }

    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    config.setAllowedHeaders(
        List.of("Authorization", "Content-Type", "X-Tenant-ID", "X-XSRF-TOKEN"));
    config.setExposedHeaders(List.of("Authorization", "X-XSRF-TOKEN"));
    config.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
      throws Exception {
    return config.getAuthenticationManager();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @ConditionalOnMissingBean
  public AuthenticationProvider authenticationProvider(
      UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(userDetailsService);
    provider.setPasswordEncoder(passwordEncoder);
    return provider;
  }
}
