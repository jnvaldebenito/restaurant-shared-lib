package com.restaurant.shared.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Utilidad para extraer la dirección IP real del cliente.
 *
 * <p>Maneja correctamente: - Cloudflare (CF-Connecting-IP) - Proxies reversos (X-Forwarded-For,
 * X-Real-IP) - Load balancers - Conexiones directas
 *
 * <p>IMPORTANTE: Previene que se use la IP del proxy/CDN en lugar de la IP real del cliente.
 */
@Slf4j
@Component
public class ClientIpResolver {

  /**
   * Headers a verificar en orden de prioridad.
   *
   * <p>Orden de prioridad: 1. CF-Connecting-IP - Cloudflare (más confiable) 2. True-Client-IP -
   * Cloudflare Enterprise 3. X-Real-IP - Nginx y otros proxies 4. X-Forwarded-For - Estándar de
   * facto (puede contener múltiples IPs) 5. Proxy-Client-IP - Apache y otros 6. WL-Proxy-Client-IP
   * - WebLogic 7. HTTP_X_FORWARDED_FOR - Variante 8. HTTP_CLIENT_IP - Variante
   */
  private static final List<String> IP_HEADERS =
      Arrays.asList(
          "CF-Connecting-IP", // Cloudflare - PRIORIDAD MÁXIMA
          "True-Client-IP", // Cloudflare Enterprise
          "X-Real-IP", // Nginx
          "X-Forwarded-For", // Estándar (puede tener múltiples IPs)
          "Proxy-Client-IP", // Apache
          "WL-Proxy-Client-IP", // WebLogic
          "HTTP_X_FORWARDED_FOR", // Variante
          "HTTP_CLIENT_IP" // Variante
          );

  /** IPs privadas y locales que deben ser ignoradas. */
  private static final List<String> PRIVATE_IP_PREFIXES =
      Arrays.asList(
          "10.", // Clase A privada
          "172.16.", // Clase B privada (172.16.0.0 - 172.31.255.255)
          "172.17.",
          "172.18.",
          "172.19.",
          "172.20.",
          "172.21.",
          "172.22.",
          "172.23.",
          "172.24.",
          "172.25.",
          "172.26.",
          "172.27.",
          "172.28.",
          "172.29.",
          "172.30.",
          "172.31.",
          "192.168.", // Clase C privada
          "127.", // Loopback
          "169.254.", // Link-local
          "::1", // IPv6 loopback
          "fc00:", // IPv6 private
          "fd00:", // IPv6 private
          "fe80:" // IPv6 link-local
          );

  /**
   * Extrae la dirección IP real del cliente desde el request.
   *
   * @param request HttpServletRequest
   * @return IP del cliente o "unknown" si no se puede determinar
   */
  public String resolveClientIp(HttpServletRequest request) {
    if (request == null) {
      log.warn("Request is null, cannot resolve client IP");
      return "unknown";
    }

    // Intentar extraer IP de headers en orden de prioridad
    for (String header : IP_HEADERS) {
      String ip = extractIpFromHeader(request, header);
      if (ip != null) {
        log.debug("Resolved client IP from header '{}': {}", header, ip);
        return ip;
      }
    }

    // Fallback: usar IP remota directa
    String remoteAddr = request.getRemoteAddr();
    if (StringUtils.hasText(remoteAddr) && !"unknown".equalsIgnoreCase(remoteAddr)) {
      log.debug("Resolved client IP from remoteAddr: {}", remoteAddr);
      return remoteAddr;
    }

    log.warn("Could not resolve client IP, using 'unknown'");
    return "unknown";
  }

  /**
   * Extrae IP de un header específico.
   *
   * @param request HttpServletRequest
   * @param headerName Nombre del header
   * @return IP válida o null si no se encuentra
   */
  private String extractIpFromHeader(HttpServletRequest request, String headerName) {
    String headerValue = request.getHeader(headerName);

    if (!StringUtils.hasText(headerValue) || "unknown".equalsIgnoreCase(headerValue)) {
      return null;
    }

    // X-Forwarded-For puede contener múltiples IPs separadas por coma
    // Formato: "client, proxy1, proxy2"
    // La primera IP es la del cliente original
    if (headerValue.contains(",")) {
      String[] ips = headerValue.split(",");
      for (String ip : ips) {
        String trimmedIp = ip.trim();
        if (isValidPublicIp(trimmedIp)) {
          return trimmedIp;
        }
      }
      return null;
    }

    // Header con una sola IP
    String trimmedIp = headerValue.trim();
    if (isValidPublicIp(trimmedIp)) {
      return trimmedIp;
    }

    return null;
  }

  /**
   * Valida que la IP sea pública (no privada, no loopback).
   *
   * @param ip Dirección IP
   * @return true si es una IP pública válida
   */
  private boolean isValidPublicIp(String ip) {
    if (!StringUtils.hasText(ip) || "unknown".equalsIgnoreCase(ip)) {
      return false;
    }

    // Verificar que no sea una IP privada
    for (String prefix : PRIVATE_IP_PREFIXES) {
      if (ip.startsWith(prefix)) {
        log.debug("IP {} is private, skipping", ip);
        return false;
      }
    }

    // Validación básica de formato IPv4
    if (ip.contains(".")) {
      String[] parts = ip.split("\\.");
      if (parts.length != 4) {
        return false;
      }

      try {
        for (String part : parts) {
          int value = Integer.parseInt(part);
          if (value < 0 || value > 255) {
            return false;
          }
        }
        return true;
      } catch (NumberFormatException e) {
        return false;
      }
    }

    // Validación básica de formato IPv6
    if (ip.contains(":")) {
      // IPv6 es más complejo, aceptar si tiene formato básico
      return ip.split(":").length >= 2;
    }

    return false;
  }

  /**
   * Obtiene información de debug sobre todos los headers de IP. Útil para troubleshooting.
   *
   * @param request HttpServletRequest
   * @return String con información de debug
   */
  public String getIpDebugInfo(HttpServletRequest request) {
    StringBuilder debug = new StringBuilder("IP Headers Debug:\n");

    for (String header : IP_HEADERS) {
      String value = request.getHeader(header);
      debug.append(String.format("  %s: %s\n", header, value != null ? value : "null"));
    }

    debug.append(String.format("  RemoteAddr: %s\n", request.getRemoteAddr()));
    debug.append(String.format("  Resolved IP: %s", resolveClientIp(request)));

    return debug.toString();
  }
}
