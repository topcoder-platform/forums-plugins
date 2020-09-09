<?php
/**
 * Class GroupModel
 */
class GroupModel extends Gdn_Model {
    /** Slug for PUBLIC type. */
    const TYPE_PUBLIC = 'public';

    /** Slug for PRIVATE type. */
    const TYPE_PRIVATE = 'private';

    /** Slug for SECRET type. */
    const TYPE_SECRET = 'secret';

    const ROLE_MEMBER = 'member';

    const ROLE_LEADER = 'leader';

    /**
     * Class constructor. Defines the related database table name.
     */
    public function __construct() {
        parent::__construct('Group');
        $this->fireEvent('Init');
    }

    /**
     * Clear the groups cache.
     */
    public function clearCache() {
        $key = 'Groups';
        Gdn::cache()->remove($key);
    }

    /**
     * Define a group.
     *
     * @param $values
     */
    public function define($values) {
        if (array_key_exists('GroupID', $values)) {
            $groupID = $values['GroupID'];
            unset($values['GroupID']);

            $this->SQL->replace('Group', $values, ['GroupID' => $groupID], true);
        } else {
            // Check to see if there is a group with the same name.
            $groupID = $this->SQL->getWhere('Group', ['Name' => $values['Name']])->value('GroupID', null);

            if (is_null($groupID)) {
                // Figure out the next group ID.
                $maxGroupID = $this->SQL->select('r.GroupID', 'MAX')->from('Group r')->get()->value('GroupID', 0);
                $groupID = $maxGroupID + 1;
                $values['GroupID'] = $groupID;

                // Insert the group.
                $this->SQL->insert('Group', $values);
            } else {
                // Update the group.
                $this->SQL->update('Group', $values, ['GroupID' => $groupID])->put();
            }
        }
        $this->clearCache();
    }

    /**
     * Default Gdn_Model::get() behavior.
     *
     * Prior to 2.0.18 it incorrectly behaved like GetID.
     * This method can be deleted entirely once it's been deprecated long enough.
     *
     * @return object DataSet
     */
    public function get($orderFields = '', $orderDirection = 'asc', $limit = false, $offset = false) {
        return parent::get($orderFields, $orderDirection, $limit, $offset);
    }

    /**
     * Join a new member
     * @param $GroupID
     * @param $UserID
     * @return bool|Gdn_DataSet|object|string
     */
    public function join($GroupID, $UserID){
        $Fields = ['Role' => GroupModel::ROLE_MEMBER, 'GroupID' => $GroupID,'UserID' => $UserID, 'DateInserted' => Gdn_Format::toDateTime()];
        $result = $this->SQL->insert('UserGroup', $Fields);
        return $result;
    }

    /**
     * Set a new role for a member
     * @param $GroupID
     * @param $MemberID
     * @param $Role
     * @return bool|Gdn_DataSet|object|string
     * @throws Exception
     */
    public function setRole($GroupID, $MemberID, $Role){
        return $this->SQL->update('UserGroup')
            ->set('Role' , $Role)
            ->where('GroupID' , $GroupID)
            ->where('UserID', $MemberID)
            ->put();
    }

    /**
     * Remove a member from group
     *
     * @param $GroupID
     * @param $MemberID
     * @return bool|Gdn_DataSet|object|string|void
     */
    public function removeMember($GroupID, $MemberID){
        return $this->SQL->delete('UserGroup', ['GroupID' => $GroupID, 'UserID' => $MemberID]);
    }

    /**
     * Get leaders
     *
     * @return object DataSet
     */
    public function getLeaders($groupID, $where =[], $orderFields = '', $limit = false, $offset = false) {
        $where = array_merge(['Role' => GroupModel::ROLE_LEADER], $where);
        return $this->getUserGroups($groupID, $where, $orderFields, $limit , $offset);
    }

    /**
     * Get members
     *
     * @param $groupID
     * @param array $where
     * @param string $orderFields
     * @param bool $limit
     * @param bool $offset
     * @return object DataSet
     */
    public function getMembers($groupID, $where =[], $orderFields = '', $limit = false, $offset = false) {
        return $this->getUserGroups($groupID, $where, $orderFields , $limit, $offset);
    }

    private function getUserGroups($groupID, $where =[], $orderFields = '', $limit = false, $offset = false) {
        if ($limit === 0) {
            trigger_error("You should not supply 0 to for $limit in GroupModel->getLeaders()", E_USER_NOTICE);
        }
        if (empty($limit)) {
            $limit = c('Vanilla.Groups.PerPage', 30);
        }
        if (empty($offset)) {
            $offset = 0;
        }

        if (!is_array($where)) {
            $where = [];
        }

        $sql = $this->SQL;

        // Build up the base query. Self-join for optimization.
        $sql->select('u.*, ug.Role, ug.DateInserted')
            ->from('UserGroup ug')
            ->join('User u', 'ug.UserID = u.UserID and ug.GroupID='.$groupID)
            ->limit($limit, $offset);

        foreach ($orderFields as $field => $direction) {
            $sql->orderBy($this->addFieldPrefix($field), $direction);
        }

        $sql->where($where);

        $data = $sql->get()->resultArray();;
        return $data;
    }

    /**
     * Returns a resultset of group data related to the specified GroupID.
     *
     * @param int The GroupID to filter to.
     */
    public function getByGroupID($groupID) {
        return $this->getWhere(['GroupID' => $groupID])->firstRow();
    }

    /**
     * Save group data.
     *
     * @param array $formPostValues The group row to save.
     * @param array|false $settings Additional settings for the save.
     * @return bool|mixed Returns the group ID or false on error.
     */
    public function save($formPostValues, $settings = false) {
        // Define the primary key in this model's table.
        $this->defineSchema();

        $groupID = val('GroupID', $formPostValues);
        $ownerID = val('OwnerID', $formPostValues);
        $insert = $groupID > 0 ? false : true;

        if ($insert) {
            // Figure out the next group ID.
            $maxGroupID = $this->SQL->select('g.GroupID', 'MAX')->from('Group g')->get()->value('GroupID', 0);
            $groupID = $maxGroupID + 1;

            $this->addInsertFields($formPostValues);
            $formPostValues['GroupID'] = strval($groupID); // string for validation
        } else {
            $this->addUpdateFields($formPostValues);
        }

        // Validate the form posted values
        if ($this->validate($formPostValues, $insert)) {
            $fields = $this->Validation->schemaValidationFields();
            $fields = $this->coerceData($fields);

            if ($insert === false) {
                $this->update($fields, ['GroupID' => $groupID]);
            } else {
                $this->insert($fields);
                $this->SQL->insert(
                    'UserGroup',
                    [
                        'UserID' => $ownerID,
                        'GroupID' => $groupID,
                        'Role' => GroupModel::ROLE_LEADER,
                        'DateInserted' => Gdn_Format::toDateTime()
                    ]
                );
            }

           if (Gdn::cache()->activeEnabled()) {
                // Don't update the user table if we are just using cached permissions.
                $this->clearCache();
            }
        } else {
            $groupID = false;
        }
        return $groupID;
    }

    /**
     * Delete a group.
     *
     * @param int $groupID The ID of the group to delete.
     * @param array $options An array of options to affect the behavior of the delete.
     *
     * @return bool Returns **true** on success or **false** otherwise.
     */
    public function deleteID($groupID, $options = []) {
        $this->SQL->delete('UserGroup', ['RoleID' => $groupID]);
        return $this->SQL->delete('Group', ['RoleID' => $groupID]);
    }

    /**
     * Validate a group
     * @inheritdoc
     */
    public function validate($values, $insert = false) {

        return parent::validate($values, $insert);
    }

    /**
     * Get count of members
     * @param $groupId
     * @param null $role
     * @return mixed
     */
    public function countOfMembers($groupId, $role = null){
        $sql = $this->SQL;
        $where = ['GroupID' => $groupId];
        if($role) {
            $where['Role']= $role;
        }

        return $sql->getCount('UserGroup', $where);
    }

    /**
     * Get all groups for the specified user
     * @param $userID
     * @return array|mixed|null
     */
    public function memberOf($userID){
        $sql = $this->SQL;
        $result = $sql->select('ug.Role, ug.GroupID')
            ->from('UserGroup ug')
            ->where('UserID', $userID)
            ->get();
        return $result->result();

    }
}