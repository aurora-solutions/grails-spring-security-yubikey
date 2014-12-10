import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.YubicoResponse;
import com.yubico.client.v2.YubicoResponseStatus;
import com.yubico.client.v2.exceptions.YubicoValidationException;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityRequestHolder;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.TextEscapeUtils;
import org.springframework.util.Assert;

import javax.security.sasl.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.yubico.client.v2.YubicoClient.isValidOTPFormat;

/**
 *  processes an authentication form submission
 *  require Three parameters UserName ,Password and YubiKeyOTP
 * author: Ikram
 * Date: 12/5/14
 * Time: 12:49 PM
 *
 */

public class YubiKeyAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "j_password";
    public static final String SPRING_SECURITY_FORM_YUBIKEYOTP_KEY = "j_OTP";
    public static final String SPRING_SECURITY_LAST_USERNAME_KEY = "SPRING_SECURITY_LAST_USERNAME";

    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
    private String yubiKeyOTPParameter = SPRING_SECURITY_FORM_YUBIKEYOTP_KEY;
    private boolean postOnly = true;


    public YubiKeyAuthenticationFilter() {
        super("/j_spring_security_check");
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String yubiKeyOTP = obtainYubiKeyOTP(request);

        if (username == null) {
            username = "";
        }
        username = username.trim();

        if (password == null) {
            password = "";
        }

        if (yubiKeyOTP == null) {
            yubiKeyOTP = "";
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        HttpSession session = request.getSession(false);
        if (session != null || getAllowSessionCreation()) {
            request.getSession().setAttribute(SPRING_SECURITY_LAST_USERNAME_KEY, TextEscapeUtils.escapeEntities(username));
        }

        String yubiKeyPublicId ;
        YubicoClient client = YubicoClient.getClient(1);
        YubicoResponse responseOTP = null;
        try {
             if (isValidOTPFormat(yubiKeyOTP))
                responseOTP = client.verify(yubiKeyOTP);
             else  {
                 logger.info("Authentication Failed");
                throw new  AuthenticationServiceException("Login Fail");
             }
        } catch (YubicoValidationException e) {
            logger.info("Authentication Failed");
            throw new  AuthenticationServiceException("Login Fail");
        } catch (YubicoValidationFailure yubicoValidationFailure) {
            logger.info("Authentication Failed");
            throw new  AuthenticationServiceException("Login Fail");
        }
        if (responseOTP.getStatus() == YubicoResponseStatus.OK) {
             yubiKeyPublicId = YubicoClient.getPublicId(yubiKeyOTP);
             logger.info("Authentication Successful");
        }
        else  {
            logger.info("Authentication Failed");
            throw new  AuthenticationServiceException("Login Fail");
        }
        setDetails(request, authRequest);
        return this.getAuthenticationManager().authenticate(authRequest);

    }


    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(passwordParameter);
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }

    protected String obtainYubiKeyOTP(HttpServletRequest request){
        return request.getParameter(yubiKeyOTPParameter);
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }

    public void setUsernameParameter(String usernameParameter) {
        Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
        this.usernameParameter = usernameParameter;
    }

    public void setPasswordParameter(String passwordParameter) {
        Assert.hasText(passwordParameter, "Password parameter must not be empty or null");
        this.passwordParameter = passwordParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }


    public final String getPasswordParameter() {
        return passwordParameter;
    }

    @Override
    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        SecurityRequestHolder.set((HttpServletRequest) request, (HttpServletResponse) response);
        try {
            super.doFilter(request, response, chain);
        }
        finally {
            SecurityRequestHolder.reset();
        }
    }
}

