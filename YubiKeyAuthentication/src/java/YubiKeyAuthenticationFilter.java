import com.yubico.client.v2.YubicoClient;
import com.yubico.client.v2.YubicoResponse;
import com.yubico.client.v2.YubicoResponseStatus;
import com.yubico.client.v2.exceptions.YubicoValidationException;
import com.yubico.client.v2.exceptions.YubicoValidationFailure;
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityRequestHolder;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.yubico.client.v2.YubicoClient.isValidOTPFormat;

/**
 *  processes an authentication form submission
 *  require Three parameters UserName ,Password and YubiKeyOTP
 *  author: Ikram
 * Date: 12/5/14
 * Time: 12:49 PM
 *
 */

public class YubiKeyAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public YubiKeyAuthenticationFilter() {
        super();
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){

        String yubiKeyOneTimePassword = obtainYubiKeyOneTimePassword(request);

        if (yubiKeyOneTimePassword == null) {
            yubiKeyOneTimePassword = "";
        }
        String yubiKeyPublicId ;
        YubicoClient client = YubicoClient.getClient(1);
        YubicoResponse responseOTP = null;
        try {
             if (isValidOTPFormat(yubiKeyOneTimePassword))
                responseOTP = client.verify(yubiKeyOneTimePassword);
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
             yubiKeyPublicId = YubicoClient.getPublicId(yubiKeyOneTimePassword);
             logger.info("Authentication Successful");
        }
        else  {
            logger.info("Authentication Failed");
            throw new  AuthenticationServiceException("Login Fail");
        }

        return super.attemptAuthentication(request, response);
    }

    protected String obtainYubiKeyOneTimePassword(HttpServletRequest request){
        return   request.getParameter("j_oneTimePassword");
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

