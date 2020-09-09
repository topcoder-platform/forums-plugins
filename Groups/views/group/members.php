<?php if (!defined('APPLICATION')) exit();
include_once $this->fetchViewLocation('helper_functions');

$Session = Gdn::session();
$Group = $this->data('Group');
$Owner = Gdn::userModel()->getID($Group->OwnerID);
$Leaders = $this->data('Leaders');
$Members = $this->data('Members');

?>
<div class="Group-Header NoBanner">
    <?php echo writeGroupHeader($Group);?>
</div>
<div class="media-list-container Group-Box MemberList">
    <div class="PageControls">
        <h2 class="H media-list-heading">Leaders</h2>
    </div>
    <?php if(count($Leaders) > 0 ) {?>
        <ul class="media-list DataList">
            <?php echo writeGroupMembersWithDetails($Leaders, $Group); ?>
        </ul>
    <?php } else {
        echo '<div class="EmptyMessage">There are no group leaders.</div>';
    }?>
</div>
<div class="media-list-container Group-Box MemberList">
    <div class="PageControls">
        <h2 class="H media-list-heading">Members</h2>
        <?php
        $PagerOptions = ['Wrapper' => '<span class="PagerNub">&#160;</span><div %1$s>%2$s</div>', 'RecordCount' => $this->data('CountMembers'), 'CurrentRecords' => $Members];
        if ($this->data('_PagerUrl')) {
            $PagerOptions['Url'] = $this->data('_PagerUrl');
        }
        PagerModule::write($PagerOptions);
        ?>
    </div>
<?php if(count($Members) > 0 ) {?>
    <ul class="media-list DataList">
        <?php echo writeGroupMembersWithDetails($Members,$Group); ?>
    </ul>
    <?php
        echo '<div class="PageControls Bottom">';
        PagerModule::write($PagerOptions);
        echo '</div>';
     ?>
<?php } else {
    echo '<div class="EmptyMessage">There are no group members.</div>';
}?>
</div>

