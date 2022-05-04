package com.ead.notification.configs.security;

import io.jsonwebtoken.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Log4j2
@Component
public class JwtProvider {

    @Value("${ead.auth.jwtSecret}")
    private String jwtSecret;

    public String getSubjectJwt(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public String getClaimNameJwt(String token, String claimName){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().get(claimName).toString();
    }

    public boolean validateJwt(String token){
       try {
           Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
           return true;
       }catch(SignatureException e){
           log.error("Invalide JWT Signature: {}",e.getMessage());
       } catch (MalformedJwtException e){
           log.error("Invalide JWT Token: {}",e.getMessage());
       }catch(ExpiredJwtException e){
           log.error("JWT Token Expired: {}",e.getMessage());
       } catch (UnsupportedJwtException e){
           log.error("JWT Unsupported: {}",e.getMessage());
       } catch(IllegalArgumentException e){
           log.error("JWT claims string is empity: {}",e.getMessage());
       }
     return false;
    }
}
