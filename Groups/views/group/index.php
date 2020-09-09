<?php if (!defined('APPLICATION')) exit();
include_once $this->fetchViewLocation('helper_functions');

$Session = Gdn::session();
$Group = $this->data('Group');
$Owner = Gdn::userModel()->getID($Group->OwnerID);
$Leaders = $this->data('Leaders');
$Members = $this->data('Members');
$TotalMembers = $this->data('TotalMembers');
$bannerCssClass = $Group->Banner ? 'HasBanner':'NoBanner';

?>
<?php echo writeGroupHeader($Group, true, $Owner, $Leaders, $TotalMembers);?>

<div class="Group-Content">
    <div class="Group-Info ClearFix clearfix">
        <div class="Group-Box Group-MembersPreview">
                <div class="PageControls">
                    <h2 class="Groups H">Members</h2>
                </div>
                <?php if(count($Members) > 0 ) { ?>
                <div class="PhotoGrid PhotoGridSmall">
                    <?php echo writeGroupMembersWithPhoto($Members); ?>
                    <?php echo anchor('All Members',allMembersUrl($this->data('Group')), 'MoreWrap');?>
                </div>
                <?php }  else  {
                    echo '<div class="EmptyMessage">There are no group members.</div>';
                }?>
        </div>
    </div>
</div>

