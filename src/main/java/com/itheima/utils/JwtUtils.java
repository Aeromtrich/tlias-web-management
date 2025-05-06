package com.itheima.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

public class JwtUtils {

    // 密钥（可以存储在配置文件中）
    private static final SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // 令牌有效期（毫秒）= 5 小时
    private static final long EXPIRATION_TIME = 5 * 60 * 60 * 1000;

    /**
     * 生成 JWT 令牌
     * @param claims Map集合 令牌主题（通常是用户标识）
     * @return 生成的 JWT 字符串
     */
    public static String generateToken(Map<String, Object> claims) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiryDate = new Date(nowMillis + EXPIRATION_TIME);

        return Jwts.builder()
                .addClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SECRET_KEY)
                .compact();
    }

    /**
     * 解析 JWT 令牌
     * @param token JWT 字符串
     * @return 解析后的 Claims（声明体）
     * @throws Exception 若解析失败（例如令牌无效或已过期）
     */
    public static Claims parseToken(String token) throws Exception {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
