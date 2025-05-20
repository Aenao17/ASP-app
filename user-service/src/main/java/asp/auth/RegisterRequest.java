package asp.auth;

import asp.model.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @Schema(example = "gabi01", description = "Numele de utilizator (unic)")
    @NotBlank
    private String username;

    @Schema(example = "Parola123!", description = "Parola contului")
    @NotBlank
    private String password;

    @Schema(example = "gabi@email.com", description = "Email personal")
    @Email
    @NotBlank
    private String email;

    @Schema(example = "gabi@student.univ.ro", description = "Email instituțional")
    @Email
    private String institutionalEmail;

    @Schema(example = "Gabriel")
    @NotBlank
    private String firstName;

    @Schema(example = "Popescu")
    @NotBlank
    private String lastName;

    @Schema(example = "0712345678")
    private String phoneNumber;

    @Schema(example = "USER", description = "Rolul în cadrul aplicației")
    private Role role;
}
