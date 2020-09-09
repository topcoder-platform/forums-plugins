<?php if (!defined('APPLICATION')) exit();

$CancelUrl = $this->data('_CancelUrl');
if (!$CancelUrl) {
    $CancelUrl = '/groups';
}
?>
<div id="GroupForm" class="FormTitleWrapper GroupForm">
    <?php
    if ($this->deliveryType() == DELIVERY_TYPE_ALL) {
        echo wrap($this->data('Title'), 'h1', ['class' => 'H']);
    }
    echo '<div class="FormWrapper">';
    echo $this->Form->open(['enctype' => 'multipart/form-data']);
    echo $this->Form->errors();


    echo '<div class="P">';
    echo $this->Form->label('Name', 'Name');
    echo wrap($this->Form->textBox('Name', ['maxlength' => 100, 'class' => 'InputBox BigInput', 'spellcheck' => 'true']), 'div', ['class' => 'TextBoxWrapper']);
    echo '</div>';

    echo '<div class="P">';
    echo $this->Form->label('Description', 'Description');
    echo '<div class="TextBoxWrapper">'.$this->Form->textBox('Description', ['MultiLine' => true]).'</div>';
    echo '</div>';

    echo '<div class="P">';
    //echo $this->Form->label('Icon', 'Icon');
    echo $this->Form->imageUploadPreview('Icon');

    echo '</div>';

    echo '<div class="P">';
    // echo $this->Form->label('Banner', 'Banner');
    echo $this->Form->imageUploadPreview('Banner');
    echo '</div>';

    echo '<div class="P">';
    echo '<div><b>Privacy</b></div>';
    echo $this->Form->radioList('Type',[GroupModel::TYPE_PUBLIC => 'Public. Anyone can see the group and its content. Anyone can join.',
        GroupModel::TYPE_PRIVATE => 'Private. Anyone can see the group, but only members can see its content. People must apply or be invited to join.',
        GroupModel::TYPE_SECRET => 'Secret. Only members can see the group and view its content. People must be invited to join.'], ['Default' =>  GroupModel::TYPE_PUBLIC]);
    echo '</div>';

    echo '<div class="Buttons">';
    echo anchor(t('Cancel'), $CancelUrl, 'Button');
    echo $this->Form->button( 'Save', ['class' => 'Button Primary']);
   // echo ' '.anchor(t('Edit'), '#', 'Button WriteButton Hidden')."\n";
    echo '</div>';

    echo $this->Form->close();
    echo '</div>';
    ?>
</div>
