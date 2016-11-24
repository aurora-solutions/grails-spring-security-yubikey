/***************************************************************************** 
* Copyright 2016 Aurora Solutions 
* 
*    http://www.aurorasolutions.io 
* 
* Aurora Solutions is an innovative services and product company at 
* the forefront of the software industry, with processes and practices 
* involving Domain Driven Design(DDD), Agile methodologies to build 
* scalable, secure, reliable and high performance products.
* 
* The Grails YubiKey Authentication plugin adds authentication support for
* YubiKey, which is a is a professional Two-Factor Authentication (2FA)
* solution, to a Grails application that uses Spring Security filters.
* The plugin depends on the Spring Security Core plugin. The plugin
* authenticates YubiKey OTP (One-Time Password) using yubico-java-client.
* 
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at 
* 
*    http://www.apache.org/licenses/LICENSE-2.0 
* 
* Unless required by applicable law or agreed to in writing, software 
* distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License. 
*****************************************************************************/


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

