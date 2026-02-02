package com.restaurant.shared.validation;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

/**
 * Utilidad centralizada para sanitización y validación de entrada de usuario.
 * Previene XSS, SQL Injection, Path Traversal y otros ataques de inyección.
 * 
 * Esta clase está en restaurant-shared-lib para ser usada por todos los
 * microservicios.
 */
@Component
public class InputSanitizer {

    // Patrones de validación
    private static final Pattern ALPHANUMERIC = Pattern.compile("^[a-zA-Z0-9]+$");
    private static final Pattern ALPHANUMERIC_SPACES = Pattern.compile("^[a-zA-Z0-9\\s]+$");
    private static final Pattern ALPHANUMERIC_EXTENDED = Pattern.compile("^[a-zA-Z0-9\\s._@-]+$");
    private static final Pattern EMAIL = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern PHONE = Pattern.compile("^\\+?[1-9]\\d{1,14}$");
    private static final Pattern DOMAIN = Pattern
            .compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");

    // Patrones peligrosos (SQL Injection, XSS, Path Traversal)
    private static final Pattern SQL_INJECTION = Pattern.compile(
            "('.*(--|;|/\\*|\\*/|xp_|sp_|exec|execute|select|insert|update|delete|drop|create|alter|union|script|javascript|onerror|onload).*')|"
                    +
                    "(\\b(select|insert|update|delete|drop|create|alter|union|exec|execute|script|javascript)\\b)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern XSS = Pattern.compile(
            "(<script[^>]*>.*?</script>)|" +
                    "(<iframe[^>]*>.*?</iframe>)|" +
                    "(javascript:)|" +
                    "(onerror\\s*=)|" +
                    "(onload\\s*=)|" +
                    "(onclick\\s*=)|" +
                    "(<img[^>]*onerror)|" +
                    "(<svg[^>]*onload)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PATH_TRAVERSAL = Pattern.compile(
            "(\\.\\./)|" +
                    "(\\.\\\\)|" +
                    "(%2e%2e/)|" +
                    "(%2e%2e\\\\)|" +
                    "(\\.\\.%2f)|" +
                    "(\\.\\.%5c)",
            Pattern.CASE_INSENSITIVE);

    /**
     * Sanitiza texto general eliminando caracteres peligrosos.
     * Permite letras, números, espacios y algunos caracteres especiales seguros.
     */
    public String sanitizeText(String input) {
        if (!StringUtils.hasText(input)) {
            return input;
        }

        // Detectar patrones peligrosos
        validateNoMaliciousPatterns(input);

        // Eliminar caracteres de control y no imprimibles
        String sanitized = input.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

        // Normalizar espacios en blanco
        sanitized = sanitized.replaceAll("\\s+", " ").trim();

        return sanitized;
    }

    /**
     * Sanitiza HTML eliminando todas las etiquetas.
     * Útil para campos de texto que no deben contener HTML.
     */
    public String sanitizeHtml(String input) {
        if (!StringUtils.hasText(input)) {
            return input;
        }

        // Primero validar patrones peligrosos
        validateNoMaliciousPatterns(input);

        // Eliminar todas las etiquetas HTML
        String sanitized = input.replaceAll("<[^>]*>", "");

        // Decodificar entidades HTML comunes
        sanitized = sanitized
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
                .replace("&quot;", "\"")
                .replace("&#x27;", "'")
                .replace("&#x2F;", "/");

        // Volver a eliminar etiquetas por si se decodificaron
        sanitized = sanitized.replaceAll("<[^>]*>", "");

        return sanitizeText(sanitized);
    }

    /**
     * Valida que un string sea alfanumérico (sin espacios).
     */
    public String validateAlphanumeric(String input, String fieldName) {
        if (!StringUtils.hasText(input)) {
            throw new IllegalArgumentException(fieldName + " no puede estar vacío");
        }

        if (!ALPHANUMERIC.matcher(input).matches()) {
            throw new IllegalArgumentException(fieldName + " solo puede contener letras y números");
        }

        return input;
    }

    /**
     * Valida que un string sea alfanumérico con espacios.
     */
    public String validateAlphanumericWithSpaces(String input, String fieldName) {
        if (!StringUtils.hasText(input)) {
            throw new IllegalArgumentException(fieldName + " no puede estar vacío");
        }

        if (!ALPHANUMERIC_SPACES.matcher(input).matches()) {
            throw new IllegalArgumentException(fieldName + " solo puede contener letras, números y espacios");
        }

        return sanitizeText(input);
    }

    /**
     * Valida email.
     */
    public String validateEmail(String email) {
        if (!StringUtils.hasText(email)) {
            throw new IllegalArgumentException("Email no puede estar vacío");
        }

        String sanitized = email.trim().toLowerCase();

        if (!EMAIL.matcher(sanitized).matches()) {
            throw new IllegalArgumentException("Email inválido");
        }

        return sanitized;
    }

    /**
     * Valida teléfono.
     */
    public String validatePhone(String phone) {
        if (!StringUtils.hasText(phone)) {
            return phone;
        }

        // Eliminar espacios y guiones
        String sanitized = phone.replaceAll("[\\s-]", "");

        if (!PHONE.matcher(sanitized).matches()) {
            throw new IllegalArgumentException("Teléfono inválido");
        }

        return sanitized;
    }

    /**
     * Valida dominio.
     */
    public String validateDomain(String domain) {
        if (!StringUtils.hasText(domain)) {
            throw new IllegalArgumentException("Dominio no puede estar vacío");
        }

        String sanitized = domain.trim().toLowerCase();

        if (!DOMAIN.matcher(sanitized).matches()) {
            throw new IllegalArgumentException("Dominio inválido");
        }

        return sanitized;
    }

    /**
     * Valida que no haya patrones maliciosos (SQL Injection, XSS, Path Traversal).
     */
    public void validateNoMaliciousPatterns(String input) {
        if (!StringUtils.hasText(input)) {
            return;
        }

        if (SQL_INJECTION.matcher(input).find()) {
            throw new SecurityException("Entrada contiene patrones sospechosos de SQL Injection");
        }

        if (XSS.matcher(input).find()) {
            throw new SecurityException("Entrada contiene patrones sospechosos de XSS");
        }

        if (PATH_TRAVERSAL.matcher(input).find()) {
            throw new SecurityException("Entrada contiene patrones sospechosos de Path Traversal");
        }
    }

    /**
     * Valida longitud máxima.
     */
    public String validateMaxLength(String input, int maxLength, String fieldName) {
        if (input != null && input.length() > maxLength) {
            throw new IllegalArgumentException(
                    fieldName + " excede la longitud máxima de " + maxLength + " caracteres");
        }
        return input;
    }

    /**
     * Valida que un valor esté en una lista de valores permitidos.
     */
    public <T> T validateAllowedValue(T value, T[] allowedValues, String fieldName) {
        if (value == null) {
            throw new IllegalArgumentException(fieldName + " no puede ser nulo");
        }

        for (T allowed : allowedValues) {
            if (allowed.equals(value)) {
                return value;
            }
        }

        throw new IllegalArgumentException(
                fieldName + " debe ser uno de: " + String.join(", ",
                        java.util.Arrays.stream(allowedValues)
                                .map(Object::toString)
                                .toArray(String[]::new)));
    }

    /**
     * Sanitización completa para campos de texto libre (nombres, descripciones,
     * etc).
     */
    public String sanitizeUserInput(String input, int maxLength, String fieldName) {
        if (!StringUtils.hasText(input)) {
            return input;
        }

        // Validar longitud
        validateMaxLength(input, maxLength, fieldName);

        // Sanitizar HTML y patrones peligrosos
        String sanitized = sanitizeHtml(input);

        // Validar longitud después de sanitizar
        validateMaxLength(sanitized, maxLength, fieldName);

        return sanitized;
    }
}
