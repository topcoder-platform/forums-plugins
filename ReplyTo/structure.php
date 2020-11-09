<?php if (!defined('APPLICATION')) {
    exit();
}

if (!isset($Drop)) {
    $Drop = false;
}

if (!isset($Explicit)) {
    $Explicit = false;
}

$Database = Gdn::database();
$SQL = $Database->sql();

$Construct = $Database->structure();
$Px = $Database->DatabasePrefix;

// Add parent pointer and left/right tree structure to the comments.
$Construct
    ->table('Comment')
    ->column('ParentCommentID', 'int', 0)
    ->column('TreeLeft', 'int', 0)
    ->column('TreeRight', 'int', 0)
    ->set(FALSE, FALSE);