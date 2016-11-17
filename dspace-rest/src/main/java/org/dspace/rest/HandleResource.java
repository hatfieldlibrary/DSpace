/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 * <p>
 * http://www.dspace.org/license/
 */
package org.dspace.rest;

import org.apache.log4j.Logger;
import org.dspace.authorize.AuthorizeManager;
import org.dspace.core.Constants;
import org.dspace.handle.HandleManager;
import org.dspace.rest.common.Collection;
import org.dspace.rest.common.Community;
import org.dspace.rest.common.DSpaceObject;
import org.dspace.rest.common.Item;
import org.dspace.rest.exceptions.ContextException;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.sql.SQLException;

/**
 * Created with IntelliJ IDEA.
 * User: peterdietz
 * Date: 10/7/13
 * Time: 1:54 PM
 * To change this template use File | Settings | File Templates.
 */
@Path("/handle")
public class HandleResource extends Resource {
    private static Logger log = Logger.getLogger(HandleResource.class);

// Removed in 5.5.   --mspalti
// private static org.dspace.core.Context context;

    @GET
    @Path("/{prefix}/{suffix}")
    @Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
    public org.dspace.rest.common.DSpaceObject getObject(@PathParam("prefix") String prefix,
                                                         @PathParam("suffix") String suffix, @QueryParam("expand") String expand,
                                                         @Context HttpHeaders headers) throws WebApplicationException {
        org.dspace.core.Context context = null;

        // Added. Present in 5.5.  --mspalti
        DSpaceObject result = null;

        try {

            context = createContext(getUser(headers));

            setSpecialGroups(context, headers);

//            Set<Integer> testGroups = Group.allMemberGroupIDs(context, context.getCurrentUser());
//            // for now, this is just verifying groups.
//            log.debug("Handle: Groups length is " + testGroups.size());
//            for (Integer groupID: testGroups) {
//                log.debug("Group ID: " + groupID);
//            }


            org.dspace.content.DSpaceObject dso = HandleManager.resolveToObject(context, prefix + "/" + suffix);
            if (dso == null) {
                throw new WebApplicationException(Response.Status.NOT_FOUND);
            }

            log.debug("DSO Lookup by handle: [" + prefix + "] / [" + suffix + "] got result of: " + dso.getTypeText() + "_" + dso.getID());

            if (AuthorizeManager.authorizeActionBoolean(context, dso, org.dspace.core.Constants.READ)) {

                // Removed returns and added break statements. Present in 5.5.  --mspalti
                switch (dso.getType()) {
                    case Constants.COMMUNITY:
                        result = new Community((org.dspace.content.Community) dso, expand, context);
                        break;
                    case Constants.COLLECTION:
                        result = new Collection((org.dspace.content.Collection) dso, expand, context, null, null);
                        break;
                    case Constants.ITEM:
                        result = new Item((org.dspace.content.Item) dso, expand, context);
                        break;
                    default:
                        result = new DSpaceObject(dso);
                }
            } else {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }

            // This is necessary. Without it, processFinally will throw 500. Present in 5.5.
            context.complete();


        } catch (SQLException e) {
            processException("Could not read handle(" + prefix + "/" + suffix + "), SQLException. Message: " + e.getMessage(), context);
        } catch (ContextException e) {
            processException("Could not read handle(" + prefix + "/" + suffix + "), ContextException. Message: " + e.getMessage(), context);
        } catch (NullPointerException e) {
            log.warn("NullPointerException. Message: " + e);
        }
        finally {
            processFinally(context);
        }

        // Return DspaceObject. As in 5.5 --mspalti
        return result;
    }
}