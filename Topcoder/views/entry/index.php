<?php if (!defined('APPLICATION')) exit();

echo '<h1>'.$this->data('Title').'</h1>';
echo '<div class="FormWrapper">';
// Make sure to force this form to post to the correct place in case the view is
// rendered within another view (ie. /dashboard/entry/index/):
echo '<div class="Messages Errors">';
echo '<ul><li>';
echo $this->data('Error');
echo '</li></ul>';
echo '</div>';

echo '<div />';
