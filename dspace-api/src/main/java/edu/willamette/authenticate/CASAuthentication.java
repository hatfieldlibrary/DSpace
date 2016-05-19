package edu.willamette.authenticate;

import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas10TicketValidator;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;


/**
 * Authenticator for Central Authentication Service (CAS).
 *
 * @author Naveed Hashmi, University of Bristol based on code developed by
 *         Nordija A/S (www.nordija.com) for Center of Knowledge Technology
 *         (www.cvt.dk)
 * @author Michael Spalti, Willamette University, revised for 3.0 configuration
 *         files, redirection based on cas.service.name, LDAP attributes, and
 *         special groups.
 */

public class CASAuthentication implements AuthenticationMethod {

    /**
     * log4j category
     */
    private final static org.apache.log4j.Logger log = Logger
            .getLogger(CASAuthentication.class);

    @SuppressWarnings("unused")
    //  private static String casProxyvalidate; // URL to validate PT tickets

    // Stores user employee type (faculty,staff,student)

//    private final SpeakerToLdap ldap = new SpeakerToLdap();

    /**
     * Checks configuration value to see if auto registration is allowed.
     * (Should be true.)
     */
    public boolean canSelfRegister(Context context, HttpServletRequest request,
                                   String username) throws SQLException {
        return ConfigurationManager.getBooleanProperty("authentication-cas",
                "webui.cas.autoregister");
    }

    /**
     * Nothing to initialize.
     */
    public void initEPerson(Context context, HttpServletRequest request,
                            EPerson eperson) throws SQLException {
    }

    /**
     * We don't use a DSpace password so there is no reason to allow changes.
     */
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request, String username) throws SQLException {
        return false;
    }

    /**
     * This an implicit authentication method. An implicit method gets
     * credentials from the environment (such as an HTTP request or even Java
     * system properties) rather than the explicit username and password. For
     * example, a method that reads the X.509 certificates in an HTTPS request
     * is implicit.
     *
     * @return true if this method uses implicit authentication.
     * <p>
     * Returns true, CAS is an implicit method
     */
    public boolean isImplicit() {
        return true;
    }


    /**
     * Get list of extra groups that user implicitly belongs to. Note that this
     * method will be invoked regardless of the authentication status of the
     * user (logged-in or not) e.g. a group that depends on the client
     * network-address.
     * <p>
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
    public int[] getSpecialGroups(Context context, HttpServletRequest request) {

        return new int[0];
    }


    /**
     * Authenticate the implicit CAS credentials. This is the heart of the
     * authentication method: test the credentials for authenticity, and if
     * accepted, attempt to match (or optionally, create) an
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
     * <p>
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


        /**
         * Authentication attempts from the REST service
         * do not pass in a request object.  CAS authentication
         * is not needed by our REST client, so we can immediately
         * return.
         */
        if (request == null) {
            return BAD_ARGS;
        }

        // ticked returned by implicit CAS login
        final String ticket = request.getParameter("ticket");

        // service string used in validation
        final String service = getServiceRequest(context, request);

        log.info(LogManager.getHeader(context, "org/dspace/authenticate", "SERVICE = "
                + service));
        log.info(LogManager.getHeader(context, "login", " ticket: " + ticket));
        log.info(LogManager.getHeader(context, "login", "service: " + service));

        if (ticket != null ) {
            HashMap<String, String> map;
            try {
                // Get the CAS validation URL
                String validate = ConfigurationManager.getProperty(
                        "authentication-cas", "cas.validate.url");
                log.info(LogManager.getHeader(context, "login",
                        "CAS validate:  " + validate));

                if (validate == null) {
                    throw new ServletException(
                            "No CAS validation URL specified. You need to set property 'cas.validate.url'");
                }

                // Validate ticket (it's assumed that CAS validator returns the
                // user network ID)
                netid = validate(service, ticket, validate);

                if (netid == null) {
                    log.error("netid not returned by validation service: invalid ticket?");
                    throw new ServletException("Ticket '" + ticket
                            + "' is not valid");
                }

                // Locate the eperson in DSpace
                EPerson eperson = null;
                try {
                    log.debug("Find eperson by netid " + netid);
                    eperson = EPerson.findByNetid(context, netid.toLowerCase());
                } catch (SQLException e) {
                    log.error("cas findbynetid failed");
                    log.error(e.getStackTrace());
                }

                // If the netid matched an eperson login succeeds
                if (eperson != null) {

                    if (eperson.getRequireCertificate()) {
                        // they must use a certificate
                        return CERT_REQUIRED;
                    } else if (!eperson.canLogIn()) {
                        return BAD_ARGS;
                    }

                    // Logged in OK.
                    HttpSession session = request.getSession(false);

                    if (session != null) {
                        session.setAttribute("loginType", "CAS");
                        log.info(LogManager.getHeader(context, "org/dspace/authenticate",
                                " type=CAS"));
                    }


                    log.info("Login successful. Setting netid to  " + netid);

                    context.setCurrentUser(eperson);

                    log.debug("Current user " + context.getCurrentUser());

                    return SUCCESS;
                }

                // The user does not exist in DSpace so creates an eperson
                else {

                    if (canSelfRegister(context, request, netid)) {

                        String employeeType = null;

                        // TEMPORARILY turn off authorization
                        context.turnOffAuthorisationSystem();

                        SpeakerToLdap ldap = new SpeakerToLdap();

                        // Register new user
                        eperson = EPerson.create(context);
                        eperson.setNetid(netid);
                        // Retrieve first name, last name,
                        // email, and phone from LDAP.
                        map = ldap.getUserAttributes(context, netid);
                        eperson.setEmail(map.get("email"));
                        eperson.setFirstName(map.get("firstName"));
                        eperson.setLastName(map.get("lastName"));
                        // eperson.setMetadata("phone", map.get("phone"));

                        employeeType = map.get("employeeType");

                        eperson.setCanLogIn(true);
                        AuthenticationManager.initEPerson(context, request,
                                eperson);
                        eperson.update();
                        context.commit();

                        // restore authorization
                        context.restoreAuthSystemState();

                        context.setCurrentUser(eperson);

                        log.info(LogManager.getHeader(context, "org/dspace/authenticate",
                                netid + ":  CAS auto-register"));
                        log.info("Login successful. Setting netid to  " + netid + " and employeeType to " + employeeType);

                        return SUCCESS;

                    } else {
                        // No auto-registration for valid netid
                        log.warn(LogManager
                                .getHeader(
                                        context,
                                        "org/dspace/authenticate",
                                        netid
                                                + "  type=netid_but_no_record, cannot auto-register"));
                        return NO_SUCH_USER;
                    }
                }

            } catch (Exception e) {
                log.error(e.getStackTrace()[0]);
            }
        }
        return BAD_ARGS;
    }

    /**
     * CAS validator. Returns the NetID of the owner of the given ticket, or
     * null if the ticket isn't valid.
     *
     * @param service     the service ID for the application validating the ticket
     * @param ticket      the opaque service ticket (ST) to validate
     * @param validateURL the URL of the validation service
     */

    private static String validate(String service, String ticket,
                                   String validateURL) throws IOException, ServletException {

        String casVersion = ConfigurationManager.getProperty(
                "authentication-cas", "cas.version");

        if (casVersion == null) {
            throw new ServletException(
                    "No CAS version specified. You need to set property 'cas.version'");
        }

        if (casVersion.equals("3.2.1")) {

            Cas10TicketValidator stv = new Cas10TicketValidator(validateURL);
            Assertion assertion = null;

            try {
                assertion = stv.validate(ticket, service);

            } catch (Exception e) {
                log.error("Unexpected exception caught", e);
                throw new ServletException(e);
            }
            if (assertion == null || assertion.getPrincipal() == null)
                return null;

            String netid = assertion.getPrincipal().getName();

            log.debug("NetID returned by CAS validation: " + netid);

            netid = netid.replaceAll("@.+$", "");

            log.debug("NetID after normalization: " + netid);

            return netid;

        } else {

            throw new ServletException(
                    "Unsupported CAS version specified by property 'cas.version' -- CAS 3.2.1 supported");
        }
    }


    /**
     * Retrieves the employee type from LDAP. This attribute is used for setting
     * special groups. Called after successful login by a registered user.
     *
     * @param context
     *            the DSpace context
     * @param netid
     *            the id of the user
     * @return the employee type
     */
    // private String getEmployeeType(Context context, String netid) {

    // return ldap.employeeType;

    // }

    /**
     * Get login page to which to redirect. Returns URL (as string) to which to
     * redirect to obtain credentials (either password prompt or e.g. HTTPS port
     * for client cert.); null means no redirect.
     *
     * @param context  DSpace context, will be modified (ePerson set) upon success.
     * @param request  The HTTP request that started this operation, or null if not
     *                 applicable.
     * @param response The HTTP response from the servlet method.
     * @return fully-qualified URL or null
     */
    public String loginPageURL(Context context, HttpServletRequest request,
                               HttpServletResponse response) {

        // Gets host name from configuration.
        final String serviceURL = ConfigurationManager.getProperty(
                "authentication-cas", "cas.service.name");

        // CAS server URL
        final String authServer = ConfigurationManager.getProperty(
                "authentication-cas", "cas.server.url");

        StringBuffer url = new StringBuffer(authServer);

        // if host name defined in configuration use it for login
        // redirection.
        // Otherwise use the current request context.
        if (serviceURL != null) {
            url.append("?service=").append(request.getScheme()).append("://")
                    .append(serviceURL);
        } else {

            url.append("?service=").append(request.getScheme()).append("://")
                    .append(request.getServerName());
            // Add the URL callback
            if (request.getServerPort() != 80)
                url.append(":").append(request.getServerPort());
        }

        url.append(request.getContextPath()).append("/cas-login");

        log.info("Attempting redirect to CAS server:  " + authServer);

        return response.encodeRedirectURL(url.toString());
    }

    /**
     * Returns message key for title of the "login" page, to use in a menu
     * showing the choice of multiple login methods.
     *
     * @param context DSpace context, will be modified (ePerson set) upon success.
     * @return Message key to look up in i18n message catalog.
     */
    public String loginPageTitle(Context context) {

        return "org.dspace.eperson.CASAuthentication.title";
    }

    /**
     * Private method that returns the URL used for CAS validation.
     */
    private String getServiceRequest(Context context, HttpServletRequest request) {

        final String serviceURL = ConfigurationManager.getProperty(
                "authentication-cas", "cas.service.name");

        StringBuffer service = new StringBuffer("");
        if (serviceURL != null) {
            service.append(request.getScheme()).append("://")
                    .append(serviceURL).append(request.getContextPath())
                    .append("/cas-login");
        } else {
            service.append(request.getRequestURL().toString());
        }

        return service.toString();
    }


}