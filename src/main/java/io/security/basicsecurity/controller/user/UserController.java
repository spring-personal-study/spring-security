package io.security.basicsecurity.controller.user;


import io.security.basicsecurity.domain.Account;
import io.security.basicsecurity.domain.AccountDTO;
import io.security.basicsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDTO accountDTO) {

		// AccountDTO를 Account 타입으로 매핑해주는 라이브러리
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDTO, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		userService.createUser(account);

		return "redirect:/";
	}
}
