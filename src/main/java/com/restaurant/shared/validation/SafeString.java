package com.restaurant.shared.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

/**
 * Valida que un string no contenga patrones maliciosos (SQL Injection, XSS, Path Traversal).
 *
 * <p>Esta anotación está en restaurant-shared-lib para ser usada por todos los microservicios.
 *
 * <p>Ejemplo de uso:
 *
 * <pre>
 * public class UserDto {
 *     {@literal @}SafeString(maxLength = 100)
 *     {@literal @}NotBlank
 *     private String name;
 *
 *     {@literal @}SafeString(maxLength = 500, sanitizeHtml = true)
 *     private String description;
 * }
 * </pre>
 */
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = SafeStringValidator.class)
@Documented
public @interface SafeString {

    /**
     * Message string.
     *
     * @return the string
     */
    String message() default "Entrada contiene caracteres o patrones no permitidos";

    /**
     * Groups class [ ].
     *
     * @return the class [ ]
     */
    Class<?>[] groups() default {};

    /**
     * Payload class [ ].
     *
     * @return the class [ ]
     */
    Class<? extends Payload>[] payload() default {};

    /**
     * Longitud máxima permitida.  @return the int
     */
    int maxLength() default 255;

    /**
     * Si se debe sanitizar HTML.  @return the boolean
     */
    boolean sanitizeHtml() default true;
}
