/*
 * (C) Copyright 2018 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Florent Guillaume
 */
package org.nuxeo.ecm.platform.web.common.requestcontroller.filter;

import static org.apache.commons.lang3.StringUtils.isBlank;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Objects;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.services.config.ConfigurationService;

/**
 * Nuxeo CSRF filter, preventing CSRF attacks by rejecting dubious requests.
 *
 * @since 10.1
 */
public class NuxeoCsrfFilter implements Filter {

    private static final Log log = LogFactory.getLog(NuxeoCsrfFilter.class);

    /**
     * This configuration property can be set to "true" to disable CSRF protection.
     */
    public static final String CSRF_PROTECTION_DISABLED_PROP = "nuxeo.csrf.protection.disabled";

    @Override
    public void init(FilterConfig filterConfig) {
        // nothing to do
    }

    @Override
    public void destroy() {
        // nothing to do
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        ConfigurationService configurationService = Framework.getService(ConfigurationService.class);
        if (configurationService != null && configurationService.isBooleanPropertyTrue(CSRF_PROTECTION_DISABLED_PROP)) {
            // disabled by configuration
            chain.doFilter(request, response);
            return;
        }

        String method = request.getMethod();
        if ("GET".equals(method) || "HEAD".equals(method) || "OPTIONS".equals(method) || "TRACE".equals(method)) {
            // safe method according to RFC 7231 4.2.1
            chain.doFilter(request, response);
            return;
        }

        URI sourceURI = getSourceURI(request);
        URI targetURI = getTargetURI(request);
        if (sourceAndTargetMatch(sourceURI, targetURI)) {
            if (targetURI == null) {
                // misconfigured server or proxy headers
                log.error("Cannot determine target URL for CSRF check");
            }
            // source and target match, or not provided
            chain.doFilter(request, response);
            return;
        }

        // cross-site request forgery attempt
        String message = "CSRF check failure";
        log.warn(message + ": source: " + sourceURI + " does not match target: " + targetURI);
        response.sendError(HttpServletResponse.SC_FORBIDDEN, message);
    }

    /** Gets the source URI: the URI of the page from which the request is actually coming. */
    public URI getSourceURI(HttpServletRequest request) {
        String source = request.getHeader("Origin");
        if (isBlank(source)) {
            source = request.getHeader("Referer");
        }
        if (isBlank(source)) {
            return null;
        }
        source = source.trim();
        if ("null".equals(source)) {
            // RFC 6454 7.1 origin-list-or-null
            return null;
        }
        if (source.contains(" ")) {
            // RFC 6454 7.1 origin-list
            // keep only the first origin to simplify the logic
            source = source.substring(0, source.indexOf(' '));
        }
        try {
            return new URI(source);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /** Gets the target URI: the URI to which the browser is connecting. */
    public URI getTargetURI(HttpServletRequest request) {
        String baseURL = VirtualHostHelper.getServerURL(request, false);
        if (baseURL == null) {
            return null;
        }
        try {
            return new URI(baseURL);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    public boolean sourceAndTargetMatch(URI sourceURI, URI targetURI) {
        if (sourceURI == null || targetURI == null) {
            return true;
        }
        return Objects.equals(sourceURI.getScheme(), targetURI.getScheme()) //
                && Objects.equals(sourceURI.getHost(), targetURI.getHost()) //
                && sourceURI.getPort() == targetURI.getPort();
    }

}
