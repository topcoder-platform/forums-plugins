<?php use Vanilla\Formatting\DateTimeFormatter;

if (!defined('APPLICATION')) exit();

$Alt = false;
$Session = Gdn::session();
$sender = Gdn::controller();
foreach ($sender->data('Discussions')->result() as $discussion) {
    $Alt = !$Alt;
    $discussionUrl = discussionUrl($discussion, '', '/');
    ?>
    <tr id="<?php echo "DiscussionID_{$discussion->discussionID}"; ?>"<?php echo $Alt ? ' class="Alt"' : ''; ?>
        data-userid="<?php echo $discussion->discussionID?>">
        <td>
            <?php

            $recordUser = Gdn::userModel()->getID($discussion->InsertUserID, DATASET_TYPE_ARRAY);
            $authorBlock = new MediaItemModule(val('Name', $recordUser), userUrl($recordUser));
            $date = Gdn::getContainer()->get(DateTimeFormatter::class)->formatDate($discussion->DateInserted, true,
                DateTimeFormatter::FORCE_FULL_FORMAT);
            $authorBlock->setView('media-sm')
                ->setImage(userPhotoUrl($recordUser))
                ->addTitleMetaIf((bool)$recordUser['Banned'], wrap(t('Banned'), 'span', ['class' => 'text-danger']))
                ->addTitleMeta(plural($recordUser['CountDiscussions'], '%s discussion', '%s discussions'))
                ->addMeta($date);
               // ->addMetaIf(($viewPersonalInfo && val('RecordIPAddress', $Row)), iPAnchor($Row['RecordIPAddress']));

            echo $authorBlock;
          //  $ancestors = $this->buildBreadcrumbs($this->CategoryID);
          //  array_push($ancestors, ['Name' => $discussion->Name]);
            $category = CategoryModel::categories($discussion->CategoryID);
            echo ' <div class="MItem Category"><i>';
            //echo anchor(htmlspecialchars(val('Name', $category)), categoryUrl($discussion->CategoryID));
            echo htmlspecialchars(val('Name', $category));
            echo '</i></div> ';
            echo ' <div class="MItem Discussion"><b>';
            echo htmlspecialchars($discussion->Name);
            echo '</b></div>';
            echo '<div class="post-content userContent Expander">';
            echo  Gdn_Format::excerpt($discussion->Body, $discussion->Format);
            echo '</div>';
            ?>
        </td>
        <td class="Alt"><?php echo $discussion->Score ?></td>
        <td class="Alt"><?php echo $discussion->CountViews ?></td>
        <td class="Alt"><?php echo $discussion->CountComments ?></td>
        <td class="options column-checkbox">
            <?php
            $attr = ['title' => t('View Post'), 'target'=>'_blank', 'aria-label' => t('View Post'), 'class' => 'btn btn-icon btn-icon-sm'];
            echo anchor(dashboardSymbol('external-link', 'icon icon-text'), $discussionUrl, '', $attr);
            ?>
        </td>
    </tr>
    <?php
}
