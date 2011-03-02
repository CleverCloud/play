package controllers;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import play.Play;
import play.mvc.*;
import play.utils.*;

public class Secure extends Controller {

   @Before(unless = {"login", "authenticate", "logout", "askGoogle", "finishAuth"})
   static void checkAccess() throws Throwable {
      // Authent
      if (!session.contains("username")) {
         flash.put("url", request.method.equals("GET") ? request.url : "/"); // seems a good default


         Class securityHandler = getHandler();
         try {
            Java.invokeStaticOrParent(securityHandler, "login");
         } catch (InvocationTargetException e) {
            throw e.getTargetException();
         }
      }
      // Checks
      Check check = getActionAnnotation(Check.class);
      if (check != null) {
         check(check);
      }
      check = getControllerInheritedAnnotation(Check.class);
      if (check != null) {
         check(check);
      }
   }

   private static void check(Check check) throws Throwable {
      for (String profile : check.value()) {
         boolean hasProfile = (Boolean) Security.invoke("check", profile);
         if (!hasProfile) {
            Security.invoke("onCheckFailed", profile);
         }
      }
   }

   private static Class getHandler() throws Throwable {
      Class securityHandler = null;

      // Invoke the right login method.
      if (getControllerAnnotation(With.class) != null) {
         securityHandler = getControllerAnnotation(With.class).value()[0];
      } else {
         error(503, "La sécurité n'aurait pas dû se déclencher.");
      }

      if (Secure.class.isAssignableFrom(securityHandler)) {
         return securityHandler;
      }
   }
// ~~~ Login

   public static void login() throws Throwable {
      BasicSecure.login();


   }

   public static void logout() throws Throwable {
      Security.invoke("onDisconnect");
      session.clear();
      response.removeCookie("rememberme");
      Security.invoke("onDisconnected");
      flash.success("secure.logout");
      login();


   }

   // ~~~ Utils
   static void redirectToOriginalURL() throws Throwable {
      Security.invoke("onAuthenticated");
      String url = flash.get("url");


      if (url == null) {
         url = "/";


      }
      redirect(url);






   }

   public static class Security extends Controller {

      /**
       * @Deprecated
       *
       * @param username
       * @param password
       * @return
       */
      static boolean authentify(String username, String password) {
         throw new UnsupportedOperationException();
      }

      /**
       * This method is called during the authentication process. This is where you check if
       * the user is allowed to log in into the system. This is the actual authentication process
       * against a third party system (most of the time a DB).
       *
       * @param username
       * @param password
       * @return true if the authentication process succeeded
       */
      static boolean authenticate(String username, String password) {
         return true;
      }

      /**
       * This method checks that a profile is allowed to view this page/method. This method is called prior
       * to the method's controller annotated with the @Check method.
       *
       * @param profile
       * @return true if you are allowed to execute this controller method.
       */
      static boolean check(String profile) {
         return true;
      }

      /**
       * This method returns the current connected username
       * @return
       */
      static String connected() {
         return session.get("username");
      }

      /**
       * Indicate if a user is currently connected
       * @return  true if the user is connected
       */
      static boolean isConnected() {
         return session.contains("username");
      }

      /**
       * This method is called after a successful authentication.
       * You need to override this method if you with to perform specific actions (eg. Record the time the user signed in)
       */
      static void onAuthenticated() {
      }

      /**
       * This method is called before a user tries to sign off.
       * You need to override this method if you wish to perform specific actions (eg. Record the name of the user who signed off)
       */
      static void onDisconnect() {
      }

      /**
       * This method is called after a successful sign off.
       * You need to override this method if you wish to perform specific actions (eg. Record the time the user signed off)
       */
      static void onDisconnected() {
      }

      /**
       * This method is called if a check does not succeed. By default it shows the not allowed page (the controller forbidden method).
       * @param profile
       */
      static void onCheckFailed(String profile) {
         forbidden();
      }

      private static Object invoke(String m, Object... args) throws Throwable {
         Class security = null;
         List<Class> classes = Play.classloader.getAssignableClasses(Security.class);
         if (classes.isEmpty()) {
            security = Security.class;
         } else {
            security = classes.get(0);
         }
         try {
            return Java.invokeStaticOrParent(security, m, args);
         } catch (InvocationTargetException e) {
            throw e.getTargetException();
         }
      }

      protected static Object invokeFor(Class<? extends Secure> classFor, String m, Object... args) throws Throwable {
         Class security = null;
         List<Class> classes = Play.classloader.getAssignableClasses(Security.class);

         if (classes.isEmpty()) {
            security = Security.class;
         } else {
            classesFor:
            for (Class cl : classes) {
               // Find the Security class that adds functionalities to the current secure handler
               if (cl.isAnnotationPresent(Secure.For.class)) {
                  Class whatFor = ((Secure.For) cl.getAnnotation(Secure.For.class)).value();
                  if (whatFor.equals(classFor)) {
                     security = cl;
                     break classesFor;
                  }
               } else {
                  security = cl;
               }

            }

            if (security == null) {
               security = Security.class;
            }

         }
         try {
            return Java.invokeStaticOrParent(security, m, args);
         } catch (InvocationTargetException e) {
            throw e.getTargetException();
         }
      }
   }

   @Retention(RetentionPolicy.RUNTIME)
   @Target(ElementType.TYPE)
   public @interface For {

      public Class<? extends Secure> value() default Secure.class;
   }
}
