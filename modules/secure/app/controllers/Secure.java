package controllers;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import play.Logger;
import play.Play;
import play.classloading.ApplicationClasses.ApplicationClass;
import play.mvc.*;
import play.utils.*;

/**
 * This class cannot be used by itself.
 * @author Julien Durillon
 */
public class Secure extends Controller {

   private static final String SECURE_HANDLER = "secureHandler";

   @Before(unless = {"login", "authenticate", "logout"})
   static void checkAccess() throws Throwable {
      if (!Secure.class.isAssignableFrom(getControllerClass())) {
         // Authent
         if (!session.contains("username")) {
            flash.put("url", request.method.equals("GET") ? request.url : "/"); // seems a good default

            Class securityHandler = getHandler();
            try {
               flash.put(SECURE_HANDLER, securityHandler.getCanonicalName());
               flash.keep();

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
   }

   private static void check(Check check) throws Throwable {
      for (String profile : check.value()) {
         boolean hasProfile = (Boolean) Security.invokeFor(getHandler(), "check", profile);
         if (!hasProfile) {
            Security.invokeFor(getHandler(), "onCheckFailed", profile);
         }
      }
   }

   /**
    * Gets the Secure daughter class that is needed by the intercepted controller.
    * @return a class that exends Secure.
    * @throws Throwable
    */
   private static Class getHandler() throws Throwable {
      if (Secure.class.isAssignableFrom(getControllerClass())) {
         Logger.info("getHandler");
         if (flash.get(SECURE_HANDLER) != null) {
            Logger.info("get handler : %s", flash.get(SECURE_HANDLER));
            return Play.classloader.getClassIgnoreCase(flash.get(SECURE_HANDLER));
         } else {
            return Secure.class;
         }
      } else {
         Class securityHandler = null;

         // Invoke the right login method.
         if (getControllerAnnotation(With.class) != null) {
            securityHandler = getControllerAnnotation(With.class).value()[0];
         } else {
            error(503, "La sécurité n'aurait pas dû se déclencher.");
         }

         if (Secure.class.isAssignableFrom(securityHandler)) {
            return securityHandler;
         } else {
            return Secure.class;
         }
      }
   }

   /**
    * Fallback login
    * @throws Throwable
    */
   public static void login() throws Throwable {
      flash.keep();
      BasicSecure.login();
   }

   public static void logout() throws Throwable {
      Security.invoke("onDisconnect");
      session.clear();
      response.removeCookie("rememberme");
      Security.invoke("onDisconnected");
      flash.success("secure.logout");
      flash.keep();
      redirectToOriginalURL();
   }

   // ~~~ Utils
   static void redirectToOriginalURL() throws Throwable {
      Logger.info("handler : %s", getHandler());
      Security.invokeFor(getHandler(), "onAuthenticated");
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

      /**
       * Invokes the method m in the application class that extends Security
       * @param m The name of the method to invoke
       * @param args The args of the method
       * @return the return value of m, if any.
       * @throws Throwable
       */
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

      /**
       * Invoke the method m on the class that implements Security, and that is @For( <b>classFor</b> ).
       *
       * You should only have one classe per application that has these two constraints.
       * The first found is used.
       *
       *
       * @param classFor
       * @param m
       * @param args
       * @return
       * @throws Throwable
       */
      protected static Object invokeFor(Class<? extends Secure> classFor, String m, Object... args) throws Throwable {
         if(classFor == null) {
            throw new NullPointerException("No Secure handler.");
         }
         Class security = null;
         List<ApplicationClass> classes = Play.classes.getAssignableClasses(Security.class);

         if (classes.isEmpty()) {
            security = Security.class;
         } else {
            classesFor:
            for (ApplicationClass acl : classes) {
               // Find the Security class that adds functionalities to the current secure handler
               if (acl.javaClass.isAnnotationPresent(Secure.For.class)) {
                  Class whatFor = ((Secure.For) acl.javaClass.getAnnotation(Secure.For.class)).value();
                  if (whatFor.equals(classFor)) {
                     security = acl.javaClass;
                     break classesFor;
                  }
               } else {
                  security = acl.javaClass;
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
