<?php if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
include_once $this->fetchViewLocation('helper_functions', 'discussions', 'vanilla');
include_once $this->fetchViewLocation('helper_functions', 'categories', 'vanilla');

echo '<h1 class="H HomepageTitle">'.
    adminCheck(NULL, ['', ' ']).
    $this->data('Title').
    '</h1>';

$this->fireEvent('AfterPageTitle');
echo '<div class="PageControls Top">';
echo categorySorts();
echo '</div>';

if($this->data('WatchedCategories')) {
    echo '<h2 class="H HomepageTitle">Categories</h2>';
    $categories = $this->data('WatchedCategories');
    ?>
    <ul class="DataList CategoryList WatchedCategoryList">
        <?php
        foreach ($categories as $category) {
            writeListItem($category, 1);
        }
        ?>
    </ul>
        <?php
            echo $this->WatchedCategoriesPager->toString('more');
}

if ($this->data('Discussions')->numRows() > 0) {
    echo '<h2 class="H HomepageTitle">Discussions</h2>';
    ?>
    <ul class="DataList Discussions">
        <?php include($this->fetchViewLocation('discussions', 'Discussions', 'Vanilla'));
        ?>
    </ul>
    <?php
    echo $this->DiscussionPager->toString('more');
}



