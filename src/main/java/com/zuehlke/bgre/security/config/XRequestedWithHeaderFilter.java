package com.zuehlke.bgre.security.config;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Requires a header "X-Requested-With" header to be present for every request.
 */

@Component
public class XRequestedWithHeaderFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("X-Requested-With");
        if (header == null || header.isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "X-Requested-With Header is not present or empty");
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
