package okta

import (
	"fmt"
	"github.com/okta/okta-sdk-golang/okta"
	"github.com/okta/okta-sdk-golang/okta/query"
)

func listGroupUserIds(m interface{}, id string) ([]string, error) {
	client := getOktaClientFromMetadata(m)
	arr, _, err := client.Group.ListGroupUsers(id, nil)
	if err != nil {
		return nil, err
	}

	userIdList := make([]string, len(arr))
	for i, user := range arr {
		userIdList[i] = user.Id
	}

	return userIdList, nil
}

func assignAdminRolesToGroup(u string, r []string, client *ApiSupplement) error {
	// client := getSupplementFromMetadata(m)
	validRoles := []string{"SUPER_ADMIN", "ORG_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "APP_ADMIN", "USER_ADMIN", "MOBILE_ADMIN", "READ_ONLY_ADMIN", "HELP_DESK_ADMIN"}

	for _, role := range r {
		if contains(validRoles, role) {
			roleStruct := okta.Role{Type: role}
			_, _, err := client.AddRoleToGroup(u, roleStruct, nil)

			if err != nil {
				return fmt.Errorf("[ERROR] Error Assigning Admin Roles to Group: %v", err)
			}
		} else {
			return fmt.Errorf("[ERROR] %v is not a valid Okta role", role)
		}
	}

	return nil
}

// need to remove from all current admin roles and reassign based on terraform configs when a change is detected
func updateAdminRolesOnGroup(g string, r []string, client *ApiSupplement) error {
	// client := getSupplementFromMetadata(m)
	roles, _, err := client.ListAssignedRolesToGroup(g, nil)

	if err != nil {
		return fmt.Errorf("[ERROR] Error Updating Admin Roles On Group: %v", err)
	}

	for _, role := range roles {
		_, err := client.RemoveRoleFromGroup(g, role.Id, nil)

		if err != nil {
			return fmt.Errorf("[ERROR] Error Updating Admin Roles On Group: %v", err)
		}
	}

	err = assignAdminRolesToGroup(g, r, client)

	if err != nil {
		return err
	}

	return nil
}

func (m *ApiSupplement) AddRoleToGroup(groupId string, body okta.Role, qp *query.Params) (*okta.Role, *okta.Response, error) {
	url := fmt.Sprintf("/api/v1/groups/%v/roles", groupId)

	req, err := m.requestExecutor.NewRequest("POST", url, body)
	if err != nil {
		return nil, nil, err
	}

	var role *okta.Role
	resp, err := m.requestExecutor.Do(req, &role)
	if err != nil {
		return nil, resp, err
	}
	return role, resp, nil
}

func (m *ApiSupplement) ListAssignedRolesToGroup(groupId string, qp *query.Params) ([]*okta.Role, *okta.Response, error) {
	url := fmt.Sprintf("/api/v1/groups/%v/roles", groupId)
	if qp != nil {
		url = url + qp.String()
	}
	req, err := m.requestExecutor.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	var role []*okta.Role
	resp, err := m.requestExecutor.Do(req, &role)
	if err != nil {
		return nil, resp, err
	}
	return role, resp, nil
}

func (m *ApiSupplement) RemoveRoleFromGroup(groupId string, roleId string, qp *query.Params) (*okta.Response, error) {
	url := fmt.Sprintf("/api/v1/groups/%v/roles/%v", groupId, roleId)
	if qp != nil {
		url = url + qp.String()
	}
	req, err := m.requestExecutor.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.requestExecutor.Do(req, nil)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
