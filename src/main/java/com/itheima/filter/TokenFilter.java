package com.itheima.filter;

import com.itheima.utils.JwtUtils;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@WebFilter(filterName = "tokenFilter", urlPatterns = "/*")
@Slf4j
public class TokenFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        // 获取请求路径
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String requestURI = request.getRequestURI();
        // 登录放行
        if (requestURI.contains("/login")) {
            log.info("登录放行");
            filterChain.doFilter(request, response);
            return;
        }
        // 获取token
        String token = request.getHeader("token");
        // token为空或token字符串为空
        if (token == null || token.isEmpty()) {
            log.info("token为空");
            response.setStatus(401);
            return;
        }
        // 解析失败
        try {
            JwtUtils.parseToken(token);
        } catch (Exception e) {
            log.info("token解析失败");
            response.setStatus(401);
            return;
        }
        // 放行
        filterChain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}
