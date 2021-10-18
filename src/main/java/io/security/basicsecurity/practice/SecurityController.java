//package io.security.basicsecurity;
//
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RestController;
//
//@RestController
//public class SecurityController {
//
//    @GetMapping("/")
//    public String index() {
//        return "home";
//    }
//
//    // if enable http.formLogin().loginPage("/loginPage") in Security config
//    @GetMapping("loginPage")
//    public String loginPage() {
//        return "loginPage";
//    }
//
//    @GetMapping("/user")
//    public String user() {
//        return "welcome user";
//    }
//
//    @GetMapping("/admin/pay")
//    public String adminPay() {
//        return "welcome admin pay";
//    }
//
//    @GetMapping("/admin/**")
//    public String admin() {
//        return "welcome admin all";
//    }
//
//    @GetMapping("/expired")
//    public String expired() {
//        return "expired";
//    }
//
//}
