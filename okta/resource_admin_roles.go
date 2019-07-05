package okta

import (
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
)

func resourceAdminRoles() *schema.Resource {
	return &schema.Resource{
		Create: resourceAdminRolesCreate,
		// Exists: resourceAdminRolesExists,
		Read:   resourceAdminRolesRead,
		Update: resourceAdminRolesUpdate,
		Delete: resourceAdminRolesDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"admin_roles": &schema.Schema{
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Group Okta admin roles - ie. ['APP_ADMIN', 'USER_ADMIN']",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"target_id": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target ID, reference to existing user or group resource",
			},
			"target_type": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Target type, can either be users or groups only",
				ValidateFunc: validation.StringInSlice([]string{"users", "groups"}, false),
			},
		},
	}
}

func resourceAdminRolesCreate(d *schema.ResourceData, m interface{}) error {
	client := getSupplementFromMetadata(m)

	targetId, okID := d.GetOk("target_id")
	targetType, okType := d.GetOk("target_type")

	if okID && okType {
		// role assigning can only happen after the user is created so order matters here
		roles := convertInterfaceToStringSetNullable(d.Get("admin_roles"))
		if roles != nil {
			if err := updateAdminRoles(targetType.(string), targetId.(string), roles, client); err != nil {
				return err
			}
		}
	}

	d.SetId(targetId.(string))
	d.Set("target_type", targetType.(string))
	return resourceAdminRolesRead(d, m)
}

func resourceAdminRolesRead(d *schema.ResourceData, m interface{}) error {
	client := getSupplementFromMetadata(m)
	targetType, _ := d.GetOk("target_type")

	_, err := GetAdminRoles(d.Id(), targetType.(string), client)
	if err != nil {
		return err
	}
	// d.Set("targetId", adminRoles.TargetID)
	d.Set("targetType", targetType.(string))

	return setNonPrimitives(d, map[string]interface{}{
		// TODO
		// "adminRoles" 		: flattenAdminRoles(),
	})
}

func resourceAdminRolesUpdate(d *schema.ResourceData, m interface{}) error {
	client := getSupplementFromMetadata(m)

	targetId, okID := d.GetOk("target_id")
	targetType, okType := d.GetOk("target_type")

	if okID && okType {
		// role assigning can only happen after the user is created so order matters here
		roles := convertInterfaceToStringSetNullable(d.Get("admin_roles"))
		if roles != nil {
			if err := updateAdminRoles(targetType.(string), targetId.(string), roles, client); err != nil {
				return err
			}
		}
	}

	d.SetId(targetId.(string))
	d.Set("target_type", targetType.(string))
	return resourceAdminRolesRead(d, m)
}

func resourceAdminRolesDelete(d *schema.ResourceData, m interface{}) error {
	client := getSupplementFromMetadata(m)
	targetType, _ := d.GetOk("target_type")

	return deleteAdminRoles(targetType.(string), d.Id(), client)
}
