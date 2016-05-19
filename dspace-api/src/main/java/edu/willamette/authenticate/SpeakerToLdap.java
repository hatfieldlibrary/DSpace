package edu.willamette.authenticate;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.dspace.core.ConfigurationManager;
import org.dspace.core.Context;
import org.dspace.core.LogManager;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Hashtable;

/**

 */
public class SpeakerToLdap {

    private final static Logger log = Logger
            .getLogger(SpeakerToLdap.class);

    /**
     * LDAP settings are configured in willamette-ldap.cfg.
     */
    final String ldap_provider_url = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_provider_url");
    final String ldap_id_field = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_id_field");
    final String ldap_search_context = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_search_context");
    final String ldap_search_scope = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_search_scope");
    final String ldap_email_field = ConfigurationManager.getProperty(
            "authentication-wu", "email_field");
    final String ldap_givenname_field = ConfigurationManager.getProperty(
            "authentication-wu", "givenname_field");
    final String ldap_surname_field = ConfigurationManager.getProperty(
            "authentication-wu", "surname_field");
    final String ldap_phone_field = ConfigurationManager.getProperty(
            "authentication-wu", "phone_field");
    final String ldap_employee_type = ConfigurationManager.getProperty(
            "authentication-wu", "employee_field");
    final String adminUser = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_search.user");
    final String adminPassword = ConfigurationManager.getProperty(
            "authentication-wu", "ldap_search.password");


    /**
     * Retrieves LDAP attributes for first name, last name, email.
     * Called after successful login by a non-registered user.
     *
     * @param context the DSpace context
     * @param netid   the id of the user
     * @return HashMap of user attributes.
     */

    public HashMap<String, String> getUserAttributes(Context context,
                                                     String netid) throws ClassNotFoundException, SQLException {

        HashMap<String, String> map = new HashMap<String, String>();

        NamingEnumeration<SearchResult> attributes = getLdapAttributes(adminUser, adminPassword, context, netid);

        String dn = null;

        try {

            while (attributes.hasMoreElements()) {

                SearchResult searchResult = null;

                searchResult = attributes.next();


                if (StringUtils.isEmpty(ldap_search_context)) {
                    dn = searchResult.getName();
                } else {
                    dn = (searchResult.getName() + "," + ldap_search_context);
                }

                String attlist[] = {
                        ldap_email_field,
                        ldap_givenname_field,
                        ldap_surname_field,
                        ldap_employee_type
                };

                Attributes atts = searchResult.getAttributes();
                Attribute att;

                if (attlist[0] != null) {
                    att = atts.get(attlist[0]);
                    if (att != null) {
                        map.put("email", (String) att.get());
                    }
                }

                if (attlist[1] != null) {
                    att = atts.get(attlist[1]);
                    if (att != null) {
                        map.put("firstName", (String) att.get());
                    }
                }

                if (attlist[2] != null) {
                    att = atts.get(attlist[2]);
                    if (att != null) {
                        map.put("lastName", (String) att.get());

                    }
                }


                if (attlist[3] != null) {
                    att = atts.get(attlist[3]);
                    if (att != null) {
                        map.put("employeeType", (String) att.get());
                    }
                }

                if (attributes.hasMoreElements()) {
                    // Oh dear - more than one match
                    // Ambiguous user, can't continue

                } else {
                    log.debug(LogManager.getHeader(context, "got DN",
                            dn));
                }
            }
        } catch (NamingException e) {
            log.warn(LogManager.getHeader(context, "ldap_authentication",
                    "type=failed_auth " + e));
        }

        // Check that a dn was found. log info if no dn.
        if ((dn == null) || (dn.trim().equals(""))) {
            log.info(LogManager.getHeader(context, "failed_login",
                    "no DN found for user " + netid));
        }


        return map;

    }

    private NamingEnumeration<SearchResult> getLdapAttributes(final String adminUser, final String adminPassword,
                                                              final Context context, final String netid) {

        // The search scope to use (default to 0)
        int ldap_search_scope_value = 0;
        try {
            ldap_search_scope_value = Integer.parseInt(ldap_search_scope
                    .trim());
        } catch (NumberFormatException e) {
            // Log the error if it has been set but is invalid
            if (ldap_search_scope != null) {
                log.warn(LogManager.getHeader(context,
                        "ldap_authentication", "invalid search scope: "
                                + ldap_search_scope));
            }
        }

        // Set up environment for creating initial context
        Hashtable<String, Object> env = new Hashtable<String, Object>(11);
        env.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(javax.naming.Context.PROVIDER_URL, ldap_provider_url);

        // if defined in configuration, use credentials
        if ((adminUser != null) && (!adminUser.trim().equals(""))
                && (adminPassword != null)
                && (!adminPassword.trim().equals(""))) {
            // Use admin credentials for search
            env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "simple");
            env.put(javax.naming.Context.SECURITY_PRINCIPAL, adminUser);
            env.put(javax.naming.Context.SECURITY_CREDENTIALS,
                    adminPassword);
        } else {
            // Use anonymous authentication.
            // WU LDAP allows us to retrieve all required attributes
            // anonymously.
            env.put(javax.naming.Context.SECURITY_AUTHENTICATION, "none");
        }

        DirContext ctx = null;
        try {
            // Create initial context
            ctx = new InitialDirContext(env);

            Attributes matchAttrs = new BasicAttributes(true);
            matchAttrs.put(new BasicAttribute(ldap_id_field, netid));

            // look up attributes
            try {
                SearchControls ctrls = new SearchControls();
                ctrls.setSearchScope(ldap_search_scope_value);

                NamingEnumeration<SearchResult> answer = ctx.search(
                        ldap_provider_url + ldap_search_context,
                        "(&({0}={1}))",
                        new Object[]{ldap_id_field, netid}, ctrls);


                return answer;

            } catch (NamingException e) {
                // if the lookup fails go ahead and create a new record for
                // them because the authentication succeeded
                log.warn(LogManager.getHeader(context,
                        "ldap_attribute_lookup", "type=failed_search " + e));
            }
        } catch (NamingException e) {
            log.warn(LogManager.getHeader(context, "ldap_authentication",
                    "type=failed_auth " + e));
        } finally {
            // Close the context when we're done
            try {
                if (ctx != null) {
                    ctx.close();
                }
            } catch (NamingException e) {
            }
        }
        // No DN match found
        return null;
    }



}