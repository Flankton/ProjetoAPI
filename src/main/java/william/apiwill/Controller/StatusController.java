package william.apiwill.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusController {

    @GetMapping(path = "/api/status")
    @PreAuthorize("hasRole('ADMIN')")
    public String check() {
        return "Online";
    }

}
