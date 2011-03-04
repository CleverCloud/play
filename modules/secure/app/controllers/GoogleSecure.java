package controllers;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import models.GoogleAuthProcess;
import org.expressme.openid.Association;
import org.expressme.openid.Authentication;
import org.expressme.openid.Endpoint;
import org.expressme.openid.OpenIdManager;
import play.Logger;
import play.Play;
import play.cache.Cache;
import play.data.validation.Validation;
import play.mvc.Router;

/**
 *
 * @author judu
 */
public class GoogleSecure extends Secure {


   public static final String GOOGLEURL = "https://www.google.com/accounts/o8/site-xrds?hd=";

   public static void login() {
      Logger.debug("google login");

      askGoogle(Play.configuration.getProperty("auth.googledomain", request.domain));
   }

   static void askGoogle(String domain) {
      OpenIdManager manager = new OpenIdManager();

      Long id = GoogleAuthProcess.nextID();
      String finishID = "auth" + id.toString();

      manager.setRealm("http://" + request.domain + "/");
      Map map = new HashMap();
      map.put("id", finishID);
      manager.setReturnTo("http://" + request.domain + Router.reverse("GoogleSecure.finishAuth", map));

      Logger.debug("endpoint : %s", GOOGLEURL + domain);


      Endpoint endpoint = manager.lookupEndpoint(GOOGLEURL + domain);
      Association association = manager.lookupAssociation(endpoint);
      String authUrl = manager.getAuthenticationUrl(endpoint, association);

      GoogleAuthProcess process = new GoogleAuthProcess();
      process.manager = manager;
      process.association = association;
      process.endPoint = endpoint;

      Cache.add(finishID, process, "10min");

      Logger.debug("process : %s", Cache.get(finishID).toString());

      flash.keep("url");
      redirect(authUrl);


   }

   public static void finishAuth(String id) {

      try {
         GoogleAuthProcess process = (GoogleAuthProcess) Cache.get(id);
         if (process == null) {
            Logger.error("No Google Authentication process");
            return;
         }

         OpenIdManager manager = process.manager;
         Authentication auth = manager.getAuthentication(createRequest(request.url), process.association.getRawMacKey(), "ext1");

         Logger.debug("before invoke for");


         Boolean allowed = (Boolean) Secure.Security.invokeFor(GoogleSecure.class, "authenticate", auth.getIdentity(), "");
         if(Validation.hasErrors() || !allowed) {
            flash.keep("url");
            flash.error("secure.error");
            params.flash();
            login();
         }

         session.put("username", auth.getIdentity());
         session.put("fullName", auth.getFullname());
         session.put("firstName", auth.getFirstname());
         session.put("lastName", auth.getLastname());
         session.put("language", auth.getLanguage());
         session.put("email", auth.getEmail());

         redirectToOriginalURL();
      } catch (Throwable ex) {
         Logger.error("Exception when I don't know : %s", ex.getMessage());
      }


   }

   private static HttpServletRequest createRequest(String url) throws UnsupportedEncodingException {
      int pos = url.indexOf('?');
      if (pos == (-1)) {
         throw new IllegalArgumentException("Bad url.");
      }
      String query = url.substring(pos + 1);
      String[] urlparams = query.split("[\\&]+");
      final Map<String, String> map = new HashMap<String, String>();
      for (String param : urlparams) {
         pos = param.indexOf('=');
         if (pos == (-1)) {
            throw new IllegalArgumentException("Bad url.");
         }
         String key = param.substring(0, pos);
         String value = param.substring(pos + 1);
         map.put(key, URLDecoder.decode(value, "UTF-8"));
      }
      return (HttpServletRequest) Proxy.newProxyInstance(
              GoogleSecure.class.getClassLoader(),
              new Class[]{HttpServletRequest.class},
              new InvocationHandler() {

                 public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                    if (method.getName().equals("getParameter")) {
                       return map.get((String) args[0]);
                    }
                    throw new UnsupportedOperationException(method.getName());
                 }
              });
   }

}
