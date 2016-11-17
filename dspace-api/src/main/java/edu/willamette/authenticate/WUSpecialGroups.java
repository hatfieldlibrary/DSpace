package edu.willamette.authenticate;

import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Special groups plugin for Willamette University.
 */
public class WUSpecialGroups implements AuthenticationMethod {

    /**
     * log4j category
     */
    private static Logger log = Logger.getLogger(WUSpecialGroups.class.getSimpleName());


    /**
     * Tests whether the user is an employee.
     *
     * @param groupname group name from configuration
     * @param emptype   group name from ldap
     * @return
     */
    private static boolean isWUEmployee(String groupname, String emptype) {
        if (emptype != null) {
            return groupname.equalsIgnoreCase(emptype);
        }
        return false;
    }

    /**
     * No need to self-register here. This is done in the authentication plugin.
     */
    @Override
    public boolean canSelfRegister(Context context, HttpServletRequest request, String username) throws SQLException {
        return false;
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

        /** List container for DSpace group IDs */
        List<Integer> groupIDs = new ArrayList<Integer>();
        /** List of group names from configuration. */
        List<String> groupNames = getLDAPGroups();

        /** The EPerson has been set during authentication */
        EPerson user = context.getCurrentUser();

        log.debug("getting special groups for " + user);

        if (user != null) {

            SpeakerToLdap ldap = new SpeakerToLdap();

            HashMap<String, String> map = null;

            String netid = user.getNetid();

            try {
                map = ldap.getUserAttributes(context,
                        netid);
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (SQLException e) {
                e.printStackTrace();
            }
            String employeeType = map.get("employeeType");

            Group WUGroup = null;

            log.debug(LogManager.getHeader(context, "special_groups",
                    "Getting special groups for " + employeeType));

            for (String groupName : groupNames) {

                if (groupName != null) {
                    log.debug(LogManager.getHeader(context, "ldap_employee",
                            " Looking or group name " + groupName));

                    // Check to see if the employee type from LDAP matches
                    // matches the group defined in configuration.
                    boolean WUEmployee =
                            isWUEmployee(groupName, employeeType);
                    // If it matches, get the DSpace group ID.
                    if (WUEmployee) {
                        log.debug(LogManager.getHeader(context,
                                "ldap_employee",
                                " Is in a WU employee group: " + groupName
                                        + " = " + employeeType));
                        try {
                            WUGroup = Group.findByName(context, groupName);

                        } catch (SQLException e) {
                            log.warn(LogManager.getHeader(context,
                                    "ldap_employee",
                                    "SQLException: " + e.getMessage()));
                        }

                        if (WUGroup == null) {
                            log.warn(LogManager
                                    .getHeader(
                                            context,
                                            "special_groups",
                                            "The special group "
                                                    + groupName
                                                    + " does not exist. Alert administrator."));
                            return new int[0];
                        }

                        groupIDs.add(new Integer(WUGroup.getID()));

                    } else {
                        log.debug(LogManager.getHeader(context,
                                "ldap_employee", "Groups do not match "
                                        + employeeType + " " + groupName));
                    }
                }
            }
        } else {
            log.warn(LogManager.getHeader(context, "ldap_specialgroup",
                    "Context current user is null."));

        }


        // Prevents anonymous users from being added to this group, and the
        // second check ensures they are LDAP users
        try {
            log.debug("Got context user: " + context.getCurrentUser());
            if (!context.getCurrentUser().getEmail().equals("")) {
                String groupName = ConfigurationManager.getProperty(
                        "authentication-wu", "login.specialgroup");
                log.debug("Got group name: " + groupName);
                if ((groupName != null) && (!groupName.trim().equals(""))) {

                    Group dspaceGroup = Group.findByName(context, groupName);
                    if (dspaceGroup == null) { // Oops - the group isn't there.
                        log.warn(LogManager
                                .getHeader(context, "ldap_specialgroup",
                                        "Group defined in authentication configuration file does not exist"));
                    } else {
                        groupIDs.add(new Integer(dspaceGroup.getID()));
                    }
                }
            }

        } catch (Exception e) {
            log.warn("Unable to identify the user from Context.");
        }

        // Create Integer array containing the special groups.
        if (groupIDs.size() > 0) {
            int[] results = new int[groupIDs.size()];
            for (int i = 0; i < groupIDs.size(); i++) {
                results[i] = (groupIDs.get(i)).intValue();
            }
            return results;
        }

        return new int[0];
    }

    /**
     * Returns a list of group names that the user should be added to upon
     * successful authentication, configured in dspace.cfg.
     *
     * @return List<String> of special groups from configuration
     */
    private List<String> getLDAPGroups() {
        List<String> groupNames = new ArrayList<String>();

        String LDAPGroupConfig = null;
        LDAPGroupConfig = ConfigurationManager.getProperty(
                "authentication-wu", "special_groups");

        if (null != LDAPGroupConfig && !LDAPGroupConfig.equals("")) {
            String[] groups = LDAPGroupConfig.split("\\s*,\\s*");
            for (int i = 0; i < groups.length; i++) {

                log.debug("got group " + groups[i].trim());
                groupNames.add(groups[i].trim());
            }
        }

        return groupNames;
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

        // Nothing to do here. Authentication handled in the auth plugins.
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