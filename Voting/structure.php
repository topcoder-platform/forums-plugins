<?php if (!defined('APPLICATION')) {
    exit();
}

// Add the column PScore/NScore in Discussion :
if(!Gdn::structure()->table('Discussion')->columnExists('PScore')) {
    Gdn::structure()->table('Discussion')
        ->column('PScore', 'float', null)
        ->column('NScore', 'float', null)
        ->set(false, false);
}

// Add the column PScore/NScore in Comment :
if(!Gdn::structure()->table('Comment')->columnExists('PScore')) {
    Gdn::structure()->table('Comment')
        ->column('PScore', 'float', null)
        ->column('NScore', 'float', null)
        ->set(false, false);
}