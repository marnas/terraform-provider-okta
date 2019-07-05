package okta

import (
	"fmt"
	"github.com/okta/okta-sdk-golang/okta"
	"github.com/okta/okta-sdk-golang/okta/query"
)

type (
	AdminRole struct {
		AdminRoles []*okta.Role `json:"adminRoles,omitempty"`
		TargetID   string       `json:"targetId,omitempty"`
		TargetType string       `json:"targetType,omitempty"`
	}
)

func GetAdminRoles(id string, targetType string, client *ApiSupplement) (*AdminRole, error) {
	adminRoleList := []*okta.Role{}

	values, _, err := client.ListAssignedRolesToGroup(targetType, id, nil)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Error Getting Admin Roles from %v: %v", targetType, err)
	}

	for _, value := range values {
		adminRoleList = append(adminRoleList, &okta.Role{Type: value.Type})
	}

	adminRole := &AdminRole{
		TargetType: targetType,
		AdminRoles: adminRoleList,
		TargetID:   id,
	}

	return adminRole, nil
}

func assignAdminRolesToGroup(targetType string, targetId string, r []string, client *ApiSupplement) error {
	validRoles := []string{"SUPER_ADMIN", "ORG_ADMIN", "API_ACCESS_MANAGEMENT_ADMIN", "APP_ADMIN", "USER_ADMIN", "MOBILE_ADMIN", "READ_ONLY_ADMIN", "HELP_DESK_ADMIN"}

	for _, role := range r {
		if contains(validRoles, role) {
			roleStruct := okta.Role{Type: role}
			_, _, err := client.AddAdminRole(targetType, targetId, roleStruct, nil)

			if err != nil {
				return fmt.Errorf("[ERROR] Error Assigning Admin Roles to %v: %v", targetType, err)
			}
		} else {
			return fmt.Errorf("[ERROR] %v is not a valid Okta role", role)
		}
	}

	return nil
}

// need to remove from all current admin roles and reassign based on terraform configs when a change is detected
func updateAdminRoles(targetType string, targetId string, r []string, client *ApiSupplement) error {
	err := deleteAdminRoles(targetType, targetId, client)

	if err != nil {
		return fmt.Errorf("[ERROR] Error Updating Admin Roles On %v: %v", targetType, err)
	}

	err = assignAdminRolesToGroup(targetType, targetId, r, client)

	if err != nil {
		return err
	}

	return nil
}

func deleteAdminRoles(targetType string, targetId string, client *ApiSupplement) error {
	roles, _, err := client.ListAssignedRolesToGroup(targetType, targetId, nil)

	if err != nil {
		return fmt.Errorf("[ERROR] Error Updating Admin Roles On %v: %v", targetType, err)
	}

	for _, role := range roles {
		_, err := client.RemoveAdminRoleHelper(targetType, targetId, role.Id, nil)

		if err != nil {
			return fmt.Errorf("[ERROR] Error Updating Admin Roles On %v: %v", targetType, err)
		}
	}

	return nil
}

func (m *ApiSupplement) AddAdminRole(targetType string, targetId string, body okta.Role, qp *query.Params) (*okta.Role, *okta.Response, error) {
	url := fmt.Sprintf("/api/v1/%v/%v/roles", targetType, targetId)

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

func (m *ApiSupplement) ListAssignedRolesToGroup(targetType string, targetId string, qp *query.Params) ([]*okta.Role, *okta.Response, error) {
	url := fmt.Sprintf("/api/v1/%v/%v/roles", targetType, targetId)
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

func (m *ApiSupplement) RemoveAdminRoleHelper(targetType string, targetId string, roleId string, qp *query.Params) (*okta.Response, error) {
	url := fmt.Sprintf("/api/v1/%v/%v/roles/%v", targetType, targetId, roleId)
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
