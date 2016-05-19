package org.dspace.rest;

import org.apache.log4j.Logger;
import org.dspace.rest.common.Permission;
import org.dspace.rest.exceptions.ContextException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.sql.SQLException;

/**
 * Created by mspalti on 5/12/16.
 */
@Path("/adminStatus")
public class AdminResource extends Resource {
    private static Logger log = Logger.getLogger(AdminResource.class);

    @GET
    @Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
    public Permission getAdminPermission(@Context HttpHeaders headers, @Context HttpServletRequest request) throws WebApplicationException {
        org.dspace.core.Context context = null;
        Permission adminPermission = null;

        try {
            context = createContext(getUser(headers));

            adminPermission = new Permission(context);

            context.complete();

        } catch (ContextException e) {
            e.printStackTrace();
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            processFinally(context);
        }

        log.trace("Retrieved system administrator permission.");
        return adminPermission;

    }


}