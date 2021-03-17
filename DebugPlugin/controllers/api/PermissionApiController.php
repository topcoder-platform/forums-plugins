<?php

use Garden\Web\Exception\ClientException;
use Garden\Schema\Schema;
use Vanilla\Utility\InstanceValidatorSchema;
use Garden\Web\Data;
use Garden\Web\Exception\NotFoundException;
use Garden\Web\Exception\ServerException;
use Vanilla\ApiUtils;

/**
 * SQL API Controller for the `/sql` resource.
 */
class PermissionApiController extends AbstractApiController {

    /**
     * Get default user permissions
     * @param $userID
     * @return Data
     * @throws \Garden\Web\Exception\HttpException
     * @throws \Vanilla\Exception\PermissionException
     */
    public function index($userID) {
        $this->permission('Garden.Settings.Manage');
        if (!Gdn::userModel()->getID($userID)) {
            throw notFoundException('User');
        }
        $userPermissions = Gdn::userModel()->getPermissions($userID);
        $data = [
            'userPermissions' => $userPermissions,
        ];
        return $data;
    }

    /**
     * Get user permissions for a category
     * @param $userID
     * @param $categoryID
     * @return Data
     * @throws \Garden\Web\Exception\HttpException
     * @throws \Vanilla\Exception\PermissionException
     */
    public function get($userID, $categoryID) {
        $this->permission('Garden.Settings.Manage');

        if (!Gdn::userModel()->getID($userID)) {
            throw notFoundException('User');
        }

        $category =  CategoryModel::categories($categoryID);
        if (!$category) {
            throw notFoundException('Category');
        }
        $groupID = val('GroupID', $category, null);
        $data = [
            'GroupID' => $groupID,
            'PermsGroupView' => $groupID? GroupModel::getGroupRoleFor($userID, $groupID) : null,
            'PermsDiscussionsView' => CategoryModel::checkPermission($category, 'Vanilla.Discussions.View', true, $userID),
            'PermsDiscussionsAdd' => CategoryModel::checkPermission($category, 'Vanilla.Discussions.Add', true, $userID),
            'PermsDiscussionsEdit' => CategoryModel::checkPermission($category, 'Vanilla.Discussions.Edit', true, $userID),
            'PermsCommentsAdd' => CategoryModel::checkPermission($category, 'Vanilla.Comments.Add', true, $userID),
            'PermsDiscussionsUploads' => CategoryModel::checkPermission($category, 'Vanilla.Discussions.Uploads', true, $userID),
            'PermsCommentsUploads' => CategoryModel::checkPermission($category, 'Vanilla.Comments.Uploads', true, $userID)
        ];
        return $data;
    }
}