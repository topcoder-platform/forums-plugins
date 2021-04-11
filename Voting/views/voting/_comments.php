<?php use Vanilla\Formatting\DateTimeFormatter;

if (!defined('APPLICATION')) exit();

$Alt = false;
$Session = Gdn::session();
$sender = Gdn::controller();
foreach ($sender->data('Comments')->result() as $comment) {
    $Alt = !$Alt;
    $commentUrl = commentUrl($comment, '', '/');
    $discussionUrl = discussionUrl($comment->DiscussionID, '', '/');
    ?>
    <tr id="<?php echo "CommentID_{$comment->CommentID}"; ?>"<?php echo $Alt ? ' class="Alt"' : ''; ?>
        data-commentid="<?php echo $comment->CommentID?>">
        <td class="content-cell">
            <?php
            $recordUser = Gdn::userModel()->getID($comment->InsertUserID, DATASET_TYPE_ARRAY);
            $authorBlock = new MediaItemModule(val('Name', $recordUser), userUrl($recordUser));
            $date = Gdn::getContainer()->get(DateTimeFormatter::class)->formatDate($comment->DateInserted, true,
                DateTimeFormatter::FORCE_FULL_FORMAT);
            $authorBlock->setView('media-sm')
                ->setImage(userPhotoUrl($recordUser))
                ->addTitleMetaIf((bool)$recordUser['Banned'], wrap(t('Banned'), 'span', ['class' => 'text-danger']))
                ->addTitleMeta(plural($recordUser['CountComments'], '%s comment', '%s comments'))
                ->addMeta($date);
               // ->addMetaIf(($viewPersonalInfo && val('RecordIPAddress', $Row)), iPAnchor($Row['RecordIPAddress']));

            echo $authorBlock;
            echo '<div class="post-content userContent Expander">';
            echo  Gdn_Format::excerpt($comment->Body, $comment->Format); //Gdn_Format::to($comment->Body, $comment->Format);
            echo '</div>';
            ?>
        </td>
        <td class="Alt"><?php echo $comment->Score ?></td>
        <td class="options column-checkbox">
            <?php
            $attr = ['title' => t('View Post'), 'target'=>'_blank', 'aria-label' => t('View Post'), 'class' => 'btn btn-icon btn-icon-sm'];
            echo anchor(dashboardSymbol('external-link', 'icon icon-text'), $commentUrl, '', $attr);
            ?>
        </td>
    </tr>
    <?php
}
