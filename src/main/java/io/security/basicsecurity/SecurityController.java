package io.security.basicsecurity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index() {
        return "home";
    }

    // if enable http.formLogin().loginPage("/loginPage")
    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

}
