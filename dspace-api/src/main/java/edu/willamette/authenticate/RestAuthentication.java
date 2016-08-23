package edu.willamette.authenticate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.SQLException;
import java.util.HashMap;

/**
 * Authentication for REST API login service.  Authentication is by
 * a shared application key known only to authorized clients. The actual
 * user authentication is handled by the client.
 *
 * This authentication method provides a mechanism for implicit login and
 * auto registration via the REST API login service. Any application that
 * can provide the secret application key is assumed (implicitly) to have
 * authenticated the user.
 *
 * Created by mspalti on 12/17/15.
 */
public class RestAuthentication implements AuthenticationMethod {

    /**
     * log4j category
     */
    private final static Logger log = Logger.getLogger(RestAuthentication.class.getSimpleName());


    /**
     * Allow auto registration for REST user. User will be registered only if
     * the ldap lookup by netid returns an email address for the user.
     */
    @Override
    public boolean canSelfRegister(Context context, HttpServletRequest request, String username) throws SQLException {
        return true;
    }

    /**
     * Nothing to initialize.
     */
    @Override
    public void initEPerson(Context context, HttpServletRequest request, EPerson eperson) throws SQLException {

    }

    /**
     * No password for REST
     */
    @Override
    public boolean allowSetPassword(Context context, HttpServletRequest request, String username) throws SQLException {
        return false;
    }

    /**
     * Requires an authorization key that is provided by the REST
     * client. Since we're not authenticating against database,
     * login is implicit.
     *
     * @return
     */
    @Override
    public boolean isImplicit() {
        log.debug("returning implicit status");
        return true;
    }

    /**
     * Get list of extra groups that user implicitly belongs to. Note that this
     * method will be invoked regardless of the authentication status of the
     * user (logged-in or not) e.g. a group that depends on the client
     * network-address.
     * <p/>
     * It might make sense to implement this method by itself in a separate
     * authentication method that just adds special groups, if the code doesn't
     * belong with any existing auth method. The stackable authentication system
     * was designed expressly to separate functions into "stacked" methods to
     * keep your site-specific code modular and tidy.
     *
     * @param context A valid DSpace context.
     * @param request The request that started this operation, or null if not
     *                applicable.
     * @return array of EPerson-group IDs, possibly 0-length, but never
     * <code>null</code>.
     */
    @Override
    public int[] getSpecialGroups(Context context, HttpServletRequest request) {

        return new int[0];

    }


    /**
     * Authenticate the application key.  If the key
     * <code>EPerson</code>. If an <code>EPerson</code> is found it is set in
     * the <code>Context</code> that was passed.
     *
     * @param context  DSpace context, will be modified (ePerson set) upon success.
     * @param netid    Username (or email address) when method is explicit. Use null
     *                 for implicit method.
     * @param password Password for explicit auth, or null for implicit method.
     * @param realm    Realm is an extra parameter used by some authentication
     *                 methods, leave null if not applicable.
     * @param request  The HTTP request that started this operation, or null if not
     *                 applicable.
     * @return One of: SUCCESS, BAD_CREDENTIALS, CERT_REQUIRED, NO_SUCH_USER,
     * BAD_ARGS
     * <p/>
     * Meaning: <br>
     * SUCCESS - authenticated OK. <br>
     * BAD_CREDENTIALS - user exists, but credentials (e.g. passwd)
     * don't match <br>
     * CERT_REQUIRED - not allowed to login this way without X.509 cert.
     * <br>
     * NO_SUCH_USER - user not found using this method. <br>
     * BAD_ARGS - user/pw not appropriate for this method
     */
    public int authenticate(Context context, String netid, String password,
                            String realm, HttpServletRequest request) throws SQLException {


        String employeeType;

        /** Get the authorization key */
        String auth_key =
                ConfigurationManager.getProperty("authentication-rest", "rest_auth_key");

        log.debug("NetID: " + netid);

        log.debug("auth key from password " + password);
        log.debug("auth key from config " + auth_key);

        /**
         * If no password (authorization key) is available, pass to the next
         * authentication method.
         */
        if (password == null) {
            return BAD_ARGS;
        }

        /**
         * Check the authorization key and allow login if there's a match.
         */
        if (password.contentEquals(auth_key)) {

            // Locate the eperson in DSpace
            try {
                log.debug("context " + context.getExtraLogInfo());
                log.debug("more context " + context.isValid());

                EPerson ePerson = EPerson.findByNetid(context, netid.toLowerCase());

                log.debug("eperson: " + ePerson);

                if (ePerson != null) {

                    // Set the Context current user.
                    context.setCurrentUser(ePerson);


                    if (ePerson.getRequireCertificate()) {
                        log.debug("certificate required?");
                        return CERT_REQUIRED;
                    } else if (!ePerson.canLogIn()) {
                        return BAD_ARGS;
                    }
                    // Needed for REST???
                    // log.debug("getting session");
                    //HttpSession session = request.getSession(false);
                    //log.debug("session: " + session);
                    // if (session != null) {
                    //     log.debug("sessio is non-null");
                    //     session.setAttribute("loginType", "REST");
                    //      log.info(LogManager.getHeader(context, "authenticate",
                    //              " type=REST"));
                    //      log.debug("set session loginType attribut to REST");
                    //  }


                    // Get the user attributes from LDAP.
//                    map = getUserAttributes(context, netid);
//                    log.debug("getting employee type");
//                    // Set the employee type attribute.
//                    employeeType = map.get("employeeType");
//                    log.debug("got employee type " + employeeType);
//                    // Set any special groups - invoke the authentication manager.
//                    int[] groupIDs = AuthenticationManager.getSpecialGroups(context, request);
//                    for (int groupID : groupIDs) {
//                        log.debug("setting special group id " + groupID);
//                        context.setSpecialGroup(groupID);
//                    }
//                    log.info("Login successful. Setting netid to  " +
//                            netid +
//                            " and employeeType to " + employeeType);
                    return SUCCESS;

                }
                // The user does not exist in DSpace so creates an eperson
                else {

                    if (canSelfRegister(context, request, netid)) {


                        HashMap<String, String> map = null;

                        SpeakerToLdap ldap = new SpeakerToLdap();

                        // TEMPORARILY turn off authorization
                        context.turnOffAuthorisationSystem();

                        // Register new user
                        EPerson eperson = EPerson.create(context);
                        eperson.setNetid(netid);
                        // Retrieve first name, last name and email from LDAP.
                        map = ldap.getUserAttributes(context, netid);

                        if (StringUtils.isEmpty(map.get("email"))) {

                            log.warn("Failed to locate " + netid + " email address in LDAP.  No EPerson created.");
                            context.restoreAuthSystemState();
                            return NO_SUCH_USER;

                        } else {
                            eperson.setEmail(map.get("email"));
                            eperson.setFirstName(map.get("firstName"));
                            eperson.setLastName(map.get("lastName"));
                            employeeType = map.get("employeeType");
                            eperson.setCanLogIn(true);

                            AuthenticationManager.initEPerson(context, request, eperson);
                            eperson.update();
                            context.commit();
                            context.setCurrentUser(eperson);
                            // restore authorization
                            context.restoreAuthSystemState();

                        }

                        log.debug(LogManager.getHeader(context, "org/dspace/authenticate",
                                netid + ":  REST auto-register"));
                        log.info("Login successful. Setting netid to  " + netid + " and employeeType to " + employeeType);

                        return SUCCESS;

                    } else {
                        // No auto-registration
                        log.warn(LogManager
                                .getHeader(
                                        context,
                                        "org/dspace/authenticate",
                                        netid +
                                                "  type=netid_but_no_record, cannot auto-register"));
                        return NO_SUCH_USER;
                    }

                }

            } catch (Exception e) {
                return BAD_ARGS;
            }

        }

        return BAD_ARGS;
    }

    @Override
    public String loginPageURL(Context context, HttpServletRequest request, HttpServletResponse response) {
        return null;
    }



    /**
     * Returns message key for title of the "login" page, to use in a menu
     * showing the choice of multiple login methods.
     *
     * @param context DSpace context, will be modified (ePerson set) upon success.
     * @return Message key to look up in i18n message catalog.
     */

    public String loginPageTitle(Context context) {

        return "";
    }



}