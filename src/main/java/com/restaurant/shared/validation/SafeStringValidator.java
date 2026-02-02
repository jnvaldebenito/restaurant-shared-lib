package com.restaurant.shared.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Validador para la anotación @SafeString.
 * 
 * Esta clase está en restaurant-shared-lib para ser usada por todos los
 * microservicios.
 */
@Component
@RequiredArgsConstructor
public class SafeStringValidator implements ConstraintValidator<SafeString, String> {

    private final InputSanitizer inputSanitizer;
    private int maxLength;
    private boolean sanitizeHtml;

    @Override
    public void initialize(SafeString constraintAnnotation) {
        this.maxLength = constraintAnnotation.maxLength();
        this.sanitizeHtml = constraintAnnotation.sanitizeHtml();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isEmpty()) {
            return true; // Use @NotNull, @NotEmpty for null/empty validation
        }

        try {
            // Validar longitud
            if (value.length() > maxLength) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate(
                        "Excede la longitud máxima de " + maxLength + " caracteres").addConstraintViolation();
                return false;
            }

            // Validar patrones maliciosos
            inputSanitizer.validateNoMaliciousPatterns(value);

            // Sanitizar HTML si es necesario
            if (sanitizeHtml) {
                String sanitized = inputSanitizer.sanitizeHtml(value);
                if (!sanitized.equals(value)) {
                    context.disableDefaultConstraintViolation();
                    context.buildConstraintViolationWithTemplate(
                            "Contiene HTML o caracteres no permitidos").addConstraintViolation();
                    return false;
                }
            }

            return true;
        } catch (SecurityException e) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(e.getMessage())
                    .addConstraintViolation();
            return false;
        }
    }
}
