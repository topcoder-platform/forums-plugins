<?php if (!defined('APPLICATION')) exit();

if (!function_exists('getGroupUrl')) :
    function getGroupUrl($group) {
        if (Gdn::session()->isValid()) {
            include_once Gdn::controller()->fetchViewLocation('helper_functions', 'group');
            return groupUrl($group);
        }
        return '';
    }
endif;

if (!function_exists('optionsList')) :
    /**
     * Build HTML for group options menu.
     *
     * @param $group
     * @return DropdownModule|string
     * @throws Exception
     */
    function optionsList($group) {
        if (Gdn::session()->isValid()) {
            include_once Gdn::controller()->fetchViewLocation('helper_functions', 'group');
            return getGroupOptionsDropdown($group);
        }
        return '';
    }
endif;

if(!function_exists('hasJoinedGroup')) {
    function hasJoinedGroup($groupID) {
        if (Gdn::session()->isValid()) {
            include_once Gdn::controller()->fetchViewLocation('helper_functions', 'group');
            return getRoleInGroupForCurrentUser($groupID);
        }
        return '';
    }
}

if (!function_exists('WriteGroup')) :

    /**
     *
     *
     * @param $group
     * @param $sender
     * @param $session
     */
    function writeGroup($group, $sender, $session) {
        $cssClass = cssClass($group);
        $groupUrl = getGroupUrl($group);
        $groupName = $group->Name;
        $groupDesc = $group->Description;
        $wrapCssClass = $group->Icon ? 'hasPhotoWrap':'noPhotoWrap';
        ?>
        <li id="Group_<?php echo $group->GroupID; ?>" class="<?php echo $cssClass.' '.$wrapCssClass; ?> ">
            <?php
            echo writeGroupIcon($group, 'PhotoWrap','ProfilePhoto ProfilePhotoMedium Group-Icon');
            if (!property_exists($sender, 'CanEditGroups')) {
                // $sender->CanEditGroups = val('PermsDiscussionsEdit', CategoryModel::categories($discussion->CategoryID)) && c('Vanilla.AdminCheckboxes.Use');
            }
            ?>
            <span class="Options">
                <div class="Buttons">
                  <?php
                    if(hasJoinedGroup($group->GroupID) == null) {
                        echo anchor('Join', '/group/join/' . $group->GroupID, 'Button Popup', '');
                    }
                  ?>
                  </div>
                  <?php
                   // echo optionsList($group);
                  ?>
            </span>

            <div class="ItemContent Group">
                <div class="Title" role="heading" aria-level="3">
                    <?php echo anchor($groupName, $groupUrl); ?>
                </div>
                <div class="Description">
                    <?php echo $groupDesc;  ?>
                 </div>
            </div>
        </li>
    <?php
    }
endif;

