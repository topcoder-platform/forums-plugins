<?php if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
include_once $this->fetchViewLocation('helper_functions', 'categories', 'vanilla');

if($this->data('WatchedCategories')) {
    $categories = $this->data('WatchedCategories');
    ?>
        <?php
        foreach ($categories as $category) {
            writeListItem($category, 1);
        }
        ?>
<?php
}
