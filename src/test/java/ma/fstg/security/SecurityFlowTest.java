package ma.fstg.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityFlowTest {
    @Autowired MockMvc mvc;
    @Autowired UserDetailsService users;
    @Autowired PasswordEncoder encoder;

    @Test void publicHomeAndProtectedRoutes() throws Exception {
        mvc.perform(get("/")).andExpect(status().isOk());
        mvc.perform(get("/css/style.css")).andExpect(status().isOk());
        mvc.perform(get("/user/dashboard")).andExpect(redirectedUrl("http://localhost/login"));
        mvc.perform(get("/admin/dashboard")).andExpect(redirectedUrl("http://localhost/login"));
        mvc.perform(get("/login")).andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    private MockHttpSession login(String name,String password) throws Exception {
        return (MockHttpSession) mvc.perform(formLogin().user(name).password(password))
            .andExpect(redirectedUrl("/")).andReturn().getRequest().getSession(false);
    }

    @Test void userCanReadUserDashboardButNotAdmin() throws Exception {
        MockHttpSession session=login("user","1111");
        mvc.perform(get("/user/dashboard").session(session)).andExpect(status().isOk());
        mvc.perform(get("/admin/dashboard").session(session)).andExpect(status().isForbidden())
            .andExpect(forwardedUrl("/access-denied"));
    }

    @Test void adminCanReadBothDashboards() throws Exception {
        MockHttpSession session=login("admin","1234");
        mvc.perform(get("/user/dashboard").session(session)).andExpect(status().isOk());
        mvc.perform(get("/admin/dashboard").session(session)).andExpect(status().isOk());
    }

    @Test void wrongCredentialsAreRejected() throws Exception {
        mvc.perform(formLogin().user("user").password("wrong")).andExpect(redirectedUrl("/login?error"));
    }

    @Test void csrfAndLogout() throws Exception {
        mvc.perform(post("/login").param("username","user").param("password","1111"))
            .andExpect(status().isForbidden());
        MockHttpSession session=login("user","1111");
        mvc.perform(post("/logout").session(session)).andExpect(status().isForbidden());
        mvc.perform(post("/logout").session(session).with(csrf())).andExpect(redirectedUrl("/?logout"));
        assertThat(session.isInvalid()).isTrue();
    }

    @Test void passwordsAreStoredAsBcryptHashes() {
        String hash=users.loadUserByUsername("user").getPassword();
        assertThat(hash).startsWith("$2").isNotEqualTo("1111");
        assertThat(encoder.matches("1111",hash)).isTrue();
    }
}
