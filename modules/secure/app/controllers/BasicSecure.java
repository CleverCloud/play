package controllers;

import play.libs.Crypto;
import play.mvc.Http;
import play.data.validation.*;
import play.libs.*;
import play.utils.*;

/**
 *
 * @author judu
 */
public class BasicSecure extends Secure {

   public static void login() throws Throwable {
      Http.Cookie remember = request.cookies.get("rememberme");
      if (remember != null && remember.value.indexOf("-") > 0) {
         String sign = remember.value.substring(0, remember.value.indexOf("-"));
         String username = remember.value.substring(remember.value.indexOf("-") + 1);
         if (Crypto.sign(username).equals(sign)) {
            session.put("username", username);
            redirectToOriginalURL();
         }
      }
      flash.keep("url");
      render();
   }

   public static void authenticate(@Required String username, String password, boolean remember) throws Throwable {
      // Check tokens
      Boolean allowed = false;
      // This is the official method name
      allowed = (Boolean) Security.invokeFor(BasicSecure.class, "authenticate", username, password);
      
      if (Validation.hasErrors() || !allowed) {
         flash.keep("url");
         flash.error("secure.error");
         params.flash();
         login();
      }
      // Mark user as connected
      session.put("username", username);
      // Remember if needed
      if (remember) {
         response.setCookie("rememberme", Crypto.sign(username) + "-" + username, "30d");
      }
      // Redirect to the original URL (or /)
      redirectToOriginalURL();
   }
}
