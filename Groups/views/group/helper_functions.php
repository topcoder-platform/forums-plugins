<?php if (!defined('APPLICATION')) exit();

if (!function_exists('allMembersUrl')) {
    /**
     * Return a URL for a group.
     * @return string
     */
    function allMembersUrl($group, $page = '', $withDomain = true) {
        $group = (object)$group;
        $result = '/group/members/'.$group->GroupID;

        if ($page) {
            if ($page > 1 || Gdn::session()->UserID) {
                $result .= '/p'.$page;
            }
        }

        return url($result, $withDomain);
    }
}
if(!function_exists('getRoleInGroupForCurrentUser')) {
    function getRoleInGroupForCurrentUser($groupId, $groups = null) {
        $sender = Gdn::controller();
        if ($groups == null) {
            $groups = $sender->data('CurrentUserGroups');
        }

        foreach($groups as $group) {
            if($group->GroupID == $groupId) {
                return $group->Role;
            }
        }
        return null;
    }
}

if (!function_exists('groupUrl')) {
    /**
     * Return a URL for a group. This function is in here and not functions.general so that plugins can override.
     *
     * @param object|array $discussion
     * @param int|string $page
     * @param bool $withDomain
     * @return string
     */
    function groupUrl($group, $page = '', $withDomain = true) {
        $group = (object)$group;
        $name = Gdn_Format::url($group->Name);

        // Disallow an empty name slug in discussion URLs.
        if (empty($name)) {
            $name = 'x';
        }

        $result = '/group/'.$group->GroupID;

        if ($page) {
            if ($page > 1 || Gdn::session()->UserID) {
                $result .= '/p'.$page;
            }
        }

        return url($result, $withDomain);
    }
}

if (!function_exists('getGroupOptionsDropdown')) {
    /**
     * Constructs an options dropdown menu for a group.
     *
     * @param object|array|null $group The group to get the dropdown options for.
     * @param object|array|null $currentUserGroups
     * @return DropdownModule A dropdown consisting of discussion options.
     */
    function getGroupOptionsDropdown($group = null) {
        $dropdown = new DropdownModule('dropdown', '', 'OptionsMenu');
        $sender = Gdn::controller();
        $session = Gdn::session();

        if ($group == null) {
            $group = $sender->data('Group');
        }

        $groupID = $group->GroupID;

        //TODO: Permissions
        $canEdit = true;
       //$canClose = GroupModel::checkPermission($groupID, 'Vanilla.Groups.Close');
        $canDelete = Gdn::session()->UserID == $group->OwnerID;
        $canLeave = getRoleInGroupForCurrentUser($groupID) !== null;
        $canInviteMember = true;
        $canManageMembers = getRoleInGroupForCurrentUser($groupID) == GroupModel::ROLE_LEADER;


        $dropdown
            ->addLinkIf($canEdit, t('Edit Group'), '/group/edit/'.$groupID, 'edit')
            ->addLinkIf($canLeave, t('Leave Group'), '/group/leave/'.$groupID, 'leave', 'LeaveGroup Popup')
            ->addLinkIf($canDelete, t('Delete Group'), '/group/delete?groupid='.$groupID, 'delete', 'DeleteGroup Popup')
            //->addLinkIf($canInviteMember, t('Invite Member'), '/group/invite/'.$groupID, 'invite')
            ->addLinkIf($canManageMembers, t('Manage Members'), '/group/members/'.$groupID, 'manage');

       return $dropdown;
    }
}


if (!function_exists('writeGroupMembers')) {
    /**
     * Return URLs for group users separated by comma.
     * @return string
     */
    function writeGroupMembers($members, $separator =',') {
        for ($i = 0; $i < count($members); $i++) {
            echo userAnchor($members[$i], 'Username');
            echo  $i != count($members)-1? $separator.' ': '';
        }
    }
}

if (!function_exists('writeGroupMembersWithPhoto')) {
    /**
     * Return URLs for group members.
     * @return string
     */
    function writeGroupMembersWithPhoto($members) {
        foreach ($members as $member) {
            echo userPhoto($member, 'Username');
        }
    }
}

if (!function_exists('writeGroupMembersWithDetails')) {
    /**
     * Return a group member details.
     * @return string
     */
    function writeGroupMembersWithDetails($members, $group) {
        foreach ($members as $member) {
            $memberObj = (object)$member;
            $memberID= val('UserID', $memberObj);
            $ownerID= $group->OwnerID;
            $groupID = $group->GroupID;
            $role = val('Role', $memberObj);
            $dateInserted = val('DateInserted', $memberObj);
            ?>
            <li id="Member_<?php echo $memberID?>" class="Item  hasPhotoWrap">
                <?php  echo userPhoto($member, 'PhotoWrap'); ?>
                <span class="Options">
                    <div class="Buttons ">
                        <?php
                            if($memberID != $ownerID) {
                                if ($role == GroupModel::ROLE_LEADER) {
                                    echo anchor('Make Member', '/group/setrole/' . $groupID . '?role=' . GroupModel::ROLE_MEMBER . '&memberid=' . $memberID, 'Button MakeMember', '');
                                } else {
                                    echo anchor('Make Leader', '/group/setrole/' . $groupID . '?role=' . GroupModel::ROLE_LEADER . '&memberid=' . $memberID, 'Button MakeLeader', '');
                                }
                                echo anchor('Remove', '/group/removemember/'.$groupID.'?memberid='.$memberID,  'Button DeleteGroupMember', '');

                            }
                        ?>
                    </div>
                </span>
                <div class="ItemContent">
                    <div class="Title" role="heading" aria-level="3">
                        <?php  echo userAnchor($member, 'Username'); ?>
                    </div>
                <div class="Excerpt "></div>
                <div class="Meta">
                    <span class="MItem JoinDate">Joined <time title="<?php echo $dateInserted;?>" datetime="<?php echo $dateInserted;?>"><?php echo $dateInserted;?></time></span>
                </div>
            </div>
        </li>
<?php
        }
    }
}
if (!function_exists('writeGroupIcon')) {
    function writeGroupIcon($group, $linkCssClass, $imageCssClass) {
        $groupUrl = groupUrl($group);
        $iconUrl = '/uploads/'.$group->Icon;
        if ($group->Icon) {
            echo anchor(
                img($iconUrl, ['class' => $imageCssClass, 'aria-hidden' => 'true']),
                $groupUrl, $linkCssClass);
        }
    }
}

if (!function_exists('writeGroupBanner')) {
     function writeGroupBanner($group) {
       $bannerUrl = '\/uploads\/'.$group->Banner;
       if($group->Banner) {
          echo  '<div class="Group-Banner" style="background-image: url('.$bannerUrl.')"></div>';
        }
     }
}

if (!function_exists('writeGroupHeader')) {
    function writeGroupHeader($group, $showDetails = false, $owner = null, $leaders = null, $totalMembers = null) {
        $bannerCssClass = $group->Banner ? 'HasBanner':'NoBanner';
     ?>
        <div class="Group-Header <?php echo $bannerCssClass; ?>">
            <?php echo writeGroupBanner($group);?>
            <?php if($group->Icon) { ?>
                <div class="Photo PhotoWrap PhotoWrapLarge Group-Icon-Big-Wrap">
                    <?php echo writeGroupIcon($group, '', 'Group-Icon Group-Icon-Big');?>
                </div>
            <?php }?>
            <div class="GroupOptions OptionsMenu ButtonGroup">
                <?php echo getGroupOptionsDropdown();?>
            </div>
            <div class="Group-Header-Info">
                <h1 class="Group-Title"><?php echo anchor($group->Name, groupUrl($group)); ?></h1>
                <?php if($showDetails) { ?>
                <div class="Group-Description userContent"><?php  echo  $group->Description; ?></div>
                <div class="Meta Group-Meta Group-Info">
                    <span class="MItem ">
                        <span class="label">Owner: </span>
                        <span class="value"><?php echo userAnchor($owner, 'Username');?></span>
                    </span>
                            <span class="MItem ">
                        <span class="label">Leaders: </span>
                        <span class="value">
                            <?php echo writeGroupMembers($leaders, ','); ?>
                        </span>
                    </span>
                    <span class="MItem "><span class="label"><?php  echo  $totalMembers.' member(s)'; ?></span></span>
                    <span class="MItem "><span class="label">Created on <?php  echo  $group->DateInserted; ?></span></span>
                    <span class="MItem "><span class="label">Privacy: </span><span class="value"><?php  echo  $group->Type; ?></span></span>
                </div>
                <?php }?>
            </div>
        </div>

        <?php
    }
}
?>


