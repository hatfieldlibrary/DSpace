/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 * <p>
 * http://www.dspace.org/license/
 */
package org.dspace.rest;

import org.apache.log4j.Logger;
import org.dspace.authenticate.AuthenticationManager;
import org.dspace.authenticate.AuthenticationMethod;
import org.dspace.eperson.EPerson;
import org.dspace.rest.common.User;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * This class provide token generation, token holding and logging user into org.dspace.re
 * api. For login use method login with class org.dspace.org.dspace.re.common.User. If
 * you want to be deleted from holder, use method for logout.
 *
 * @author Rostislav Novak (Computing and Information Centre, CTU in Prague)
 *
 * @author Michael Spalti, modified to support implicit login and special groups.
 *
 */
public class TokenHolder {

    private static final Logger log = Logger.getLogger(TokenHolder.class);

    public static final String TOKEN_HEADER = "rest-dspace-token";

    private static Map<String, String> tokens = new HashMap<String, String>(); // Map with pair Email,token

    private static Map<String, EPerson> persons = new HashMap<String, EPerson>(); // Map with pair token,Eperson

    private static Map<String, int[]> groups = new HashMap<String, int[]>();

    /**
     * Login user into org.dspace.re api. It check user credentials if they are okay.
     *
     * @param user User which will be logged into org.dspace.re api.
     * @return Returns generated token, which must be used in request header
     * under org.dspace.re-api-token. If password is bad or user does not exist,
     * it returns NULL.
     * @throws WebApplicationException It is thrown by SQLException if user could not be read from
     *                                 database. And by Authorization exception if context has not
     *                                 permission to read eperson.
     *                                 <p>
     *                                 NOTE: In this implementation, the user.email is the user's netId.  The user.password
     *                                 is the authorization token for the client application.
     */
    public static String login(User user) throws WebApplicationException {

        org.dspace.core.Context context = null;
        String token = null;

        try {

            log.info("getting context ");
            context = new org.dspace.core.Context();
            EPerson ePerson = null;
            // Set<Integer> specialGroups = null;

            log.info("Seeking auth status ");
            /**
             * Let AuthenticationManager handle calls authenticate methods in stack;
             */
            int authStatus = AuthenticationManager.authenticate(context, user.getEmail(), user.getPassword(), null, null);

            log.info("Got auth status " + authStatus);

            if (authStatus == AuthenticationMethod.SUCCESS) {
                ePerson = context.getCurrentUser();

            }


            synchronized (TokenHolder.class) {

                // This indicates failed login
                if ((ePerson == null)) {
                    token = null;
                    log.debug("Null eperson");
                }

                // Use existing token.
                else if (tokens.containsKey(ePerson.getID())) {
                    log.debug("Got eperson id: " + ePerson.getID());
                    token = tokens.get(Integer.toString(ePerson.getID()));
                }
                // Or create new token.
                else {

                    token = generateToken();
                    persons.put(token, ePerson);
                    tokens.put(Integer.toString(ePerson.getID()), token);

                    /**
                     * Use AuthenticationManager to retrieve all special groups.
                     * Our special groups plugin accepts null for the request parameter.
                     */
                    int[] gps = AuthenticationManager.getSpecialGroups(context, null);

                    /**
                     * Add special groups for this token
                     */
                    groups.put(token, gps);
//                    /**
//                     * Add special groups to the current context.
//                     */
//                    for (int i = 0; i < gps.length; i++) {
//                        context.setSpecialGroup(gps[i]);
//
//
//                    }
//                    // TEST
//                    specialGroups = Group.allMemberGroupIDs(context, ePerson);
//                    // for now, this is just verifying groups.
//                    log.debug("Groups length is " + specialGroups.size());
//                    for (Integer groupID: specialGroups) {
//
//                        log.debug("Group ID: " + groupID);
//                    }
                }

            }

            log.trace("User has been logged in.");
            context.complete();

        } catch (SQLException e) {
            context.abort();
            log.error("Could not read user from database. Message:" + e);
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            if ((context != null) && (context.isValid())) {
                context.abort();
                log.error("Something get wrong. Aborting context in finally statement.");
                throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
            }
        }

        return token;
    }

    /**
     * Return EPerson for log into context.
     *
     * @param token Token under which is stored eperson.
     * @return Return instance of EPerson if is token right, otherwise it
     * returns NULL.
     */
    public static synchronized EPerson getEPerson(String token) {

        return persons.get(token);

    }

    public static synchronized  int[] getGroups(String token) {
        // Make sure we have a valid token.
        if (token != null) {
            return groups.get(token);
        }
        return null;

    }

    /**
     * Logout user from org.dspace.re api. It delete token and EPerson from TokenHolder.
     *
     * @param token Token under which is stored eperson.
     * @return Return true if was all okay, otherwise return false.
     */
    public static synchronized boolean logout(String token) {
        if ((token == null) || (persons.get(token) == null)) {
            return false;
        }
        String email = persons.get(token).getEmail();
        EPerson person = persons.remove(token);
        // remove special groups
        groups.remove(token);
        if (person == null) {
            return false;
        }
        tokens.remove(email);
        return true;
    }

    /**
     * It generates unique token.
     *
     * @return String filled with unique token.
     */
    private static String generateToken() {
        return UUID.randomUUID().toString();
    }



}