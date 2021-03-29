<?php 
use Vanilla\FeatureFlagHelper;
if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
$User = $Session->User;
$CssClass = '';
$transientKey = Gdn::session()->transientKey();

if ($this->CssClass)
    $CssClass .= ' '.$this->CssClass;

$DashboardCount = 0;
$ModerationCount = 0;
// Spam & Moderation Queue
if ($Session->checkPermission(['Garden.Settings.Manage', 'Garden.Moderation.Manage', 'Moderation.Spam.Manage', 'Moderation.ModerationQueue.Manage'], false)) {
    $LogModel = new LogModel();
    //$SpamCount = $LogModel->getOperationCount('spam');
    $ModerationCount = $LogModel->getOperationCount('moderate,pending');
    $DashboardCount += $ModerationCount;
}
// Applicant Count
if ($Session->checkPermission('Garden.Users.Approve')) {
    $RoleModel = new RoleModel();
    $ApplicantCount = $RoleModel->getApplicantCount();
    $DashboardCount += $ApplicantCount;
} else {
    $ApplicantCount = null;
}

$useNewFlyouts = FeatureFlagHelper::featureEnabled('NewFlyouts');

$this->EventArguments['DashboardCount'] = &$DashboardCount;
$this->fireEvent('BeforeFlyoutMenu');

if ($Session->isValid()):
    echo '<div class="MeBox'.$CssClass.'">';
    if (!$useNewFlyouts) {
        echo userPhoto($User);
    }
    echo '<div class="WhoIs">';
    if (!$useNewFlyouts) {
        echo userAnchor($User, 'Username');
    }
    echo '<div class="MeMenu">';
    // Notifications
    $CountNotifications = $User->CountNotifications;
    // $CNotifications = is_numeric($CountNotifications) && $CountNotifications > 0 ? '<span class="Alert NotificationsAlert">'.$CountNotifications.'</span>' : '';
    echo '<span class="ToggleFlyout" rel="/profile/notificationspopin?TransientKey=' . htmlspecialchars(urlencode($transientKey)) . '">';
    $notificationImage = '<svg width="16" height="16" viewBox="0 0 16 16" xmlns="http://www.w3.org/2000/svg"><g fill="none" fill-rule="evenodd"><path fill="#FFF" fill-rule="nonzero" d="M10 14c0 1.1-.9 2-2 2s-2-.9-2-2h4zm5-3c.6 0 1 .4 1 1s-.4 1-1 1H1c-.6 0-1-.4-1-1s.4-1 1-1h.5C2.2 10.3 3 9.3 3 8V5c0-2.8 2.2-5 5-5s5 2.2 5 5v3c0 1.3.8 2.3 1.5 3h.5z" id="a"></path></g></svg>';
    echo anchor($notificationImage, userUrl($User), 'MeButton FlyoutButton MeButton-notifications js-clear-notifications', ['title' => t('Notifications'), 'tabindex' => '0', "role" => "button", "aria-haspopup" => "true"]);
    //echo anchor(sprite('SpNotifications', 'Sprite Sprite16', t('Notifications')) . $CNotifications, userUrl($User), 'MeButton FlyoutButton MeButton-notifications js-clear-notifications', ['title' => t('Notifications'), 'tabindex' => '0', "role" => "button", "aria-haspopup" => "true"]);
    if(is_numeric($CountNotifications) && $CountNotifications > 0){
        echo sprite('SpAlert', 'Sprite');
    }
    echo '<div class="Flyout FlyoutMenu Flyout-withFrame"></div></span>';

    // Inbox
    $showInbox = false;
    if ($showInbox && Gdn::addonManager()->lookupAddon('conversations')) {
        $CountInbox = val('CountUnreadConversations', Gdn::session()->User);
        $CInbox = is_numeric($CountInbox) && $CountInbox > 0 ? ' <span class="Alert">'.$CountInbox.'</span>' : '';
        echo '<span class="ToggleFlyout" rel="/messages/popin">';
        echo anchor(sprite('SpInbox', 'Sprite Sprite16', t('Inbox')).$CInbox, '/messages/all', 'MeButton FlyoutButton', ['title' => t('Inbox'), 'tabindex' => '0', "role" => "button", "aria-haspopup" => "true"]);
        echo sprite('SpFlyoutHandle', 'Arrow');
        echo '<div class="Flyout FlyoutMenu Flyout-withFrame"></div></span>';
    }

    // Bookmarks
    $showBookmarks = false;
    if ($showBookmarks && Gdn::addonManager()->lookupAddon('Vanilla')) {
        echo '<span class="ToggleFlyout" rel="/discussions/bookmarkedpopin">';
        echo anchor(sprite('SpBookmarks', 'Sprite Sprite16', t('Bookmarks')), '/discussions/bookmarked', 'MeButton FlyoutButton', ['title' => t('Bookmarks'), 'tabindex' => '0', "role" => "button", "aria-haspopup" => "true"]);
        echo sprite('SpFlyoutHandle', 'Arrow');
        echo '<div class="Flyout FlyoutMenu Flyout-withFrame"></div></span>';
    }

    // Profile Settings & Logout
    $dropdown = new DropdownModule();
    $dropdown->setData('DashboardCount', $DashboardCount);
    $triggerTitle = t('Account Options');

    if ($useNewFlyouts) {
        $imgUrl = userPhotoUrl($User);
        $triggerIcon = "<span><img class='ProfilePhoto ProfilePhotoSmall' src='$imgUrl'/><span class='Username'>".$User->Name."</span><span class='icon icon-chevron-down'></span></span>";
    } else {
        $triggerIcon = sprite('SpOptions', 'Sprite Sprite16', $triggerTitle);
    }

    $dropdown->setTrigger('', 'anchor', 'MeButton FlyoutButton MeButton-user TopcoderMeButton', $triggerIcon, '/profile', ['title' => $triggerTitle, 'tabindex' => '0', "role" => "button", "aria-haspopup" => "true", "id"=>"meButton"]);

    $emptyTopModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonTopMItem'];
    $dropdown->addText('', '', '', '', $emptyTopModifiers);

    $profileHtml = '<div class="flex middle"><img src="' . $imgUrl . '" width="60" class="avatar" alt="avatar">
    <div class="flex column left">
        <span class="handle">' . Gdn::session()->User->Name . '</span>
        <span class="email">' . Gdn::session()->User->Email . '</span>
    </div></div>';
    $profilesModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonProfileMItem'];
    $dropdown->addLink($profileHtml, 'https://topcoder.com/members/'.Gdn::session()->User->Name, '','link-profile-details flex middle', '', $profilesModifiers);

    $switchToCommunityHtml = '<img class="switch-icon" src="https://www.topcoder.com/wp-content/themes/tc3-marketing/nav/image/icon-switch-business.svg" alt="switch">
    <span class="switch-to-business">Switch to BUSINESS</span>';
    $switchToCommunityModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonSwitchToBusinessMItem'];
    $dropdown->addLink($switchToCommunityHtml, 'https://www.topcoder.com', '', 'switch-to-business middle', '', $switchToCommunityModifiers);

    //  $editModifiers['listItemCssClasses'] = ['EditProfileWrap', 'link-editprofile'];
    //  $dropdown->addLinkIf(hasViewProfile(Gdn::session()->UserID), t('View Profile'), '/profile', 'profile.view', '', [], $editModifiers);

    $preferencesModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonSettingsItem'];
    // $dropdown->addLinkIf(hasEditProfile(Gdn::session()->UserID), 'Settings', '/profile/preferences', 'profile.preferences', '', [], $preferencesModifiers);
    $dropdown->addLink('Settings', 'https://www.topcoder.com/settings/profile', 'profile.preferences', '', [], $preferencesModifiers);

    // $applicantModifiers = $ApplicantCount > 0 ? ['badge' => $ApplicantCount] : [];
    // $applicantModifiers['listItemCssClasses'] = ['link-applicants'];
    //  $modModifiers = $ModerationCount > 0 ? ['badge' => $ModerationCount] : [];
    //  $modModifiers['listItemCssClasses'] = ['link-moderation'];
    //  $spamModifiers['listItemCssClasses'] = ['link-spam'];
    //  $dashboardModifiers['listItemCssClasses'] = ['link-dashboard'];
    $helpModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonHelpItem'];
    $signoutModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonSignOutItem'];

    //  $spamPermission = $Session->checkPermission(['Garden.Settings.Manage', 'Garden.Moderation.Manage', 'Moderation.ModerationQueue.Manage'], false);
    //  $modPermission = $Session->checkPermission(['Garden.Settings.Manage', 'Garden.Moderation.Manage', 'Moderation.ModerationQueue.Manage'], false);
    //  $dashboardPermission = $Session->checkPermission(['Garden.Settings.View', 'Garden.Settings.Manage'], false);

    // $dropdown->addLinkIf('Garden.Users.Approve', t('Applicants'), '/dashboard/user/applicants', 'moderation.applicants', '', [], $applicantModifiers);
    //  $dropdown->addLinkIf($spamPermission, t('Spam Queue'), '/dashboard/log/spam', 'moderation.spam', '', [], $spamModifiers);
    //  $dropdown->addLinkIf($modPermission, t('Moderation Queue'), '/dashboard/log/moderation', 'moderation.moderation', '', [], $modModifiers);
    //  $dropdown->addLinkIf($dashboardPermission, t('Dashboard'), '/dashboard/settings', 'dashboard.dashboard', '', [], $dashboardModifiers);

    $dropdown->addLink('Help', 'https://help.topcoder.com/hc/en-us', 'topcoder.help', '', [], $helpModifiers);
    $dividerModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonDividerMItem'];
    $dropdown->addLink('Log Out', signOutUrl(), 'entry.signout', '', [], $signoutModifiers);

    $emptyBottomModifiers['listItemCssClasses'] = ['MeButtonMenuItem', 'MeButtonBottomMItem'];
    $dropdown->addText('', 'entry.bottom', '', '', $emptyBottomModifiers);

    $this->EventArguments['Dropdown'] = &$dropdown;
    $this->fireEvent('FlyoutMenu'); ?>
<?php
    echo $dropdown;
    if ($useNewFlyouts) {
        echo "<button class='MeBox-mobileClose'>×</button>";
    }
    echo '</div>';
    echo '</div>';
    echo '</div>';
else:
    echo '<div class="MeBox MeBox-SignIn'.$CssClass.'">';

    echo '<div class="SignInLinks">';

    echo anchor(t('Login'), signInUrl($this->_Sender->SelfUrl), (signInPopup() ? ' SignInPopup' : ''), ['rel' => 'nofollow']);
    // $Url = registerUrl($this->_Sender->SelfUrl);
    // if (!empty($Url)) {
       // echo bullet(' ').anchor(t('Register'), $Url, 'ApplyButton', ['rel' => 'nofollow']).' ';
    // }
    echo '</div>';

    echo ' <div class="SignInIcons">';
    $this->fireEvent('SignInIcons');
    echo '</div>';

    echo '</div>';
endif;
