<?php if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
include_once $this->fetchViewLocation('helper_functions');

echo '<div class="groupToolbar"><a href="/group/add" class="Button Primary groupToolbar-newGroup">New Group</a></div>';

echo '<div class="media-list-container Group-Box my-groups">';
        echo '<div class="PageControls">';
        echo '<h2 class="H HomepageTitle">'.$this->data('Title').'</h2>';
        echo '</div>';
    //$Description = $this->data('Category.Description', $this->description());
    //echo wrapIf(Gdn_Format::htmlFilter($Description), 'div', ['class' => 'P PageDescription']);

    $PagerOptions = ['Wrapper' => '<span class="PagerNub">&#160;</span><div %1$s>%2$s</div>', 'RecordCount' => $this->data('CountGroups'), 'CurrentRecords' => $this->data('Groups')->numRows()];
    if ($this->data('_PagerUrl')) {
        $PagerOptions['Url'] = $this->data('_PagerUrl');
    }
    echo '<div class="PageControls">';
        PagerModule::write($PagerOptions);
        //echo Gdn_Theme::module('NewDiscussionModule', $this->data('_NewDiscussionProperties', ['CssClass' => 'Button Action Primary']));
        // Avoid displaying in a category's list of discussions.
     echo '</div>';

    if ($this->GroupData->numRows() > 0 ) {
        ?>
        <h2 class="sr-only"><?php echo t('Group List'); ?></h2>
        <ul class="media-list DataList">
            <?php include($this->fetchViewLocation('groups')); ?>
        </ul>
        <?php

        echo '<div class="PageControls Bottom">';
        PagerModule::write($PagerOptions);
       // echo Gdn_Theme::module('NewDiscussionModule', $this->data('_NewDiscussionProperties', ['CssClass' => 'Button Action Primary']));
        echo '</div>';

    } else {
        ?>
        <div class="Empty"><?php echo t('No groups were found.'); ?></div>
    <?php
    }
echo '</div>';