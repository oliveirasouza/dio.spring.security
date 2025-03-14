package dio.dio.spring.security;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {

    @GetMapping
    public String welcome() {
        return "Welcome to DIO Spring Security!";
    }

    @GetMapping("/users")
      public String users() {
        return "Autorized user!";
    }

    @GetMapping("/managers")
    public String managers() {
        return "Autorized MANAGERS!";
    }
}
