package io.security;

import io.security.basicsecurity.controller.login.LoginController;
import io.security.basicsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.basicsecurity.security.token.AjaxAuthenticationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
public class AjaxLoginProcessTest {

    private MockMvc mockMvc;

    @InjectMocks
    private LoginController loginController;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(loginController)
                .build();
    }

    @Test
    @DisplayName("ajax 통신을 통해 인증을 요청하는 경우 AjaxLoginProcessingFilter 가 1번이라도 수행되는지 검증/")
    public void RunAjaxFilterAtLeastOnceTest() throws Exception {

        final MockHttpServletRequest[] request = new MockHttpServletRequest[1];

        MockHttpServletResponse response = mockMvc.perform(post("/api/login")
                                                  .content("{\"username\":\"user\", \"password\":\"1111\"}")
                                                  .with(req -> {
                                                      req.addHeader("X-Requested-With", "XMLHttpRequest");
                                                      request[0] = req;
                                                      return req;
                                                  })
                                                  .contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("success"))
                .andReturn()
                .getResponse();


        // TODO: Filter 테스트 기법을 익히고 나서 다시 테스트해볼 것
        //AjaxLoginProcessingFilter mockFilter = Mockito.mock(AjaxLoginProcessingFilter.class);
        //given(mockFilter.attemptAuthentication(request[0], response)).willReturn(new AjaxAuthenticationToken("user", "1111"));
        //verify(mockFilter, atLeastOnce()).attemptAuthentication(request[0], response);

    }

}
