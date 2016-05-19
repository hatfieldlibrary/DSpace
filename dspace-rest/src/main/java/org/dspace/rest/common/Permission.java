package org.dspace.rest.common;

import org.dspace.authorize.AuthorizeManager;
import org.dspace.core.Context;

import javax.xml.bind.annotation.XmlRootElement;
import java.sql.SQLException;

/**
 * Container for user permissions on the dspace object.
 *
 * @author Michael Spalti
 */
@XmlRootElement(name = "permission")
public class Permission {

    /**
     * Whether user can write to an item
     */
    private boolean canWrite = false;
    /**
     * Whether user can submit an item.
     */
    private boolean canSubmit = false;

    /**
     * Whether user has adminstration privileges on the object.
     */
    private boolean canAdminister = false;

    private boolean isSystemAdmin = false;

    public Permission() {}

    /**
     * Constructor used to check for system administrator.
     * @param context
     */
    public Permission(Context context) {
        try {
            this.isSystemAdmin = AuthorizeManager.isAdmin(context);
        } catch (SQLException e) {
            e.printStackTrace();
        }

    }

    /**
     * Constructor used for permissions on a specific dspace object.
     * @param canSubmit
     * @param canAdminister
     * @param canWrite
     */
    public Permission(boolean canSubmit, boolean canAdminister, boolean canWrite) {

        this.canSubmit = canSubmit;
        this.canAdminister = canAdminister;
        this.canWrite = canWrite;

    }

    public void setCanSubmit(boolean canSubmit)
    {
        this.canSubmit = canSubmit;
    }

    public boolean getCanSubmit() {
        return this.canSubmit;
    }

    public void setCanAdminister(boolean canAdminister)
    {
        this.canAdminister = canAdminister;
    }

    public boolean getCanAdminister() {
        return this.canAdminister;
    }

    public void setCanWrite(boolean canWrite)
    {
        this.canWrite = canWrite;
    }

    public boolean getCanWrite() {
        return this.canWrite;
    }

    public void setSystemAdmin(boolean isSystemAdmin) {
        this.isSystemAdmin = isSystemAdmin;
    }

    public boolean getSystemAdmin() {
        return this.isSystemAdmin;
    }


}