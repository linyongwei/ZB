package api.security.jwt;

import api.entity.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.text.SimpleDateFormat;
import java.util.Date;

public class JwtUtil {
    public static int time=30*60*1000;
    public static String getToken(User user){
        String token="";
        token= JWT.create().withAudience(user.getId())
                .withJWTId(user.getId())
                .withSubject("admin")
                .withExpiresAt(new Date(System.currentTimeMillis()+time))
                .sign(Algorithm.HMAC256(user.getPassword()));
        return token;
     }
    public static Boolean isTokenExpired(String token) {
        try {
            final Date expiration = JWT.decode(token).getExpiresAt();
            return expiration.before(new Date());
        } catch (TokenExpiredException expiredJwtException) {
            return true;
        }
    }
    public static boolean isNextToExpired(String token){
        Date date=JWT.decode(token).getExpiresAt();
        return date.getTime()-System.currentTimeMillis()<5*60*1000;
    }

}
