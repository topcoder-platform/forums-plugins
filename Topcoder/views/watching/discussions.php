<?php if (!defined('APPLICATION')) exit();
$Session = Gdn::session();
include_once $this->fetchViewLocation('helper_functions', 'discussions', 'vanilla');

if ($this->data('Discussions')->numRows() > 0) {
    ?>

    <?php include($this->fetchViewLocation('discussions', 'Discussions', 'Vanilla')); ?>

<?php
}
