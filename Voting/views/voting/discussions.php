<?php if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
$sender = Gdn::controller();
?>
    <h1><?php echo $sender->data('Title'); ?></h1>
    <div class="toolbar">
        <div class="toolbar-main">
            <?php
            $count = $sender->data('RecordCount', null);
           // if ($count !== null) {
              //  echo sprintf('%s discussions.', $count);
           // }
            ?>
        </div>
        <?php PagerModule::write(['Sender' => $this, 'View' => 'pager-dashboard']); ?>
    </div>
    <div class="table-wrap">
        <table id="Users" class="table-data js-tj">
            <thead>
            <tr>
                <th class="column-lg"><?php echo t('Discussion'); ?></th>
                <th class="column-md"><?php echo anchor(t('Total Votes'), $this->_OrderDiscussionsUrl('totalvotes')); ?></th>
                <th class="column-md"><?php echo anchor(t('Up Votes'), $this->_OrderDiscussionsUrl('votesup')); ?></th>
                <th class="column-md"><?php echo anchor(t('Down Votes'), $this->_OrderDiscussionsUrl('votesdown')); ?></th>
                <th class="column-md"><?php echo anchor(t('Comments'), $this->_OrderDiscussionsUrl('comments')); ?></th>
                <th class="options column-checkbox"></th>
            </tr>
            </thead>
            <tbody>
            <?php include($this->fetchViewLocation('_discussions')); ?>
            </tbody>
        </table>
    </div>