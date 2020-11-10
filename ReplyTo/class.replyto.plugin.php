<?php
use Garden\Schema\Schema;
use Garden\Web\Data;
use Garden\Web\Exception\ClientException;
use Garden\Web\Exception\NotFoundException;
use Vanilla\ApiUtils;

class ReplyToPlugin extends Gdn_Plugin {

    const QUERY_PARAMETER_VIEW='view';
    const VIEW_FLAT = 'flat';
    const VIEW_TREE = 'tree';
    const VIEW_THREADED = 'threaded';

    private $replyToModel;
    /**
     * Configure the plugin instance.
     *
     */
    public function __construct(ReplyToModel $replyToModel) {
        $this->replyToModel = $replyToModel;
    }

    /**
     * Database updates.
     */
    public function structure() {
        include __DIR__.'/structure.php';
    }

    /**
     * Run once on enable.
     *
     * @throws Gdn_UserException
     */
    public function setup() {
        // Initial data hasn't been inserted
        if(!c('Garden.Installed')) {
            return;
        }
        $this->structure();
    }

    /**
     * OnDisable is run whenever plugin is disabled.
     *
     * @return void.
     */
    public function onDisable() {
        // nothing
    }

    /**
     * Load CSS into head for the plugin
     * @param $sender
     */
    public function assetModel_styleCss_handler($sender) {
        $sender->addCssFile('replyto.css', 'plugins/ReplyTo');
    }

    // Set JS for this plugin.
    protected function prepareController(&$sender) {
       $sender->addJsFile('replyto.js', 'plugins/ReplyTo');
    }

    public function discussionController_render_before(&$sender) {
        $this->prepareController($sender);
    }

    public function postController_render_before($sender) {
        $this->prepareController($sender);
    }

    /**
     * Render View options for a discussion
     * @param $sender
     * @param $args
     */
    public function base_Replies_handler($sender, $args){
        $discussion = $sender->data('Discussion');
        if (!$discussion) {
            return;
        }

        if (isset($args['Comment'])) {
            return;
        }

        $discussionUrl = discussionUrl($discussion, '', '/');
        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW, self::VIEW_FLAT);

        echo '<div class="ReplyViewOptions"><span class="MLabel">View:&nbsp</span>';
        echo anchor('Flat', $discussionUrl.'?'.self::QUERY_PARAMETER_VIEW.'='.self::VIEW_FLAT, $viewMode == self::VIEW_FLAT?'Active':'').'&nbsp;&nbsp;|&nbsp;&nbsp;';
        echo anchor('Threaded', $discussionUrl.'?'.self::QUERY_PARAMETER_VIEW.'='.self::VIEW_THREADED, $viewMode == self::VIEW_THREADED?'Active':'').'&nbsp;&nbsp;|&nbsp;&nbsp;';
        echo anchor('Tree', $discussionUrl.'?'.self::QUERY_PARAMETER_VIEW.'='.self::VIEW_TREE, $viewMode == self::VIEW_TREE?'Active':'');
        echo '</div>';
    }

    /**
     * Set the tree order of all comments in the model as soon as it is instantiated.
     * It is not clear if there are other plugins that may also wish to change the ordering.
     * @param $sender
     */
    public function commentModel_afterConstruct_handler(&$sender) {
        self::log('commentModel_afterConstruct_handler', ['path'=> Gdn::request()->pathAndQuery()]);
        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW, self::VIEW_FLAT);
        if($viewMode == self::VIEW_TREE || $viewMode == self::VIEW_THREADED) {
            $sender->orderBy(array('TreeLeft asc', 'DateInserted asc'));
        }
    }

    public function postController_afterCommentSave_handler($Sender,$args) {
        self::log('postController_afterCommentSave_handler', ['ParentCommentID' => $args['Comment']->ParentCommentID]);
        // Only if inserting a new comment, we want to insert it into the tree.
        // Two things seem to indicate we are inserting new: the CommentID is empty and
        // the "Editing" flag is empty. We will check both to make sure.
        if (empty($Sender->EventArguments['Editing']) || empty($Sender->EventArguments['CommentID'])) {
            $Details = $this->replyToModel->insertPrep(
                $Sender->EventArguments['Comment']->DiscussionID,
                $Sender->EventArguments['Comment']->ParentCommentID,
                $Sender->EventArguments['Comment']->CommentID
            );
        }
    }

    public function commentModel_deleteComment_handler(&$Sender) {
        self::log('commentModel_deleteComment_handler', []);
        if (empty($Sender->EventArguments['CommentID']))  {
            return;
        }

        $CommentID = $Sender->EventArguments['CommentID'];
        $Comment = $this->replyToModel->getComment($CommentID);
        if (empty($Comment)) {
            return;
        }

        $this->replyToModel->onDeleteComment($Comment);
     }

    /**
     * Before the comments are rendered, go through them and work out their (relative) depth and give them classes.
     * @param $sender
     * @param $args
     */
    public function discussionController_beforeDiscussionRender_handler($sender, $args) {
        self::log('discussionController_beforeDiscussionRender_handler', []);
        if (!Gdn::session()->isValid()) {
            return;
        }

        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW, self::VIEW_FLAT);
        if($viewMode == self::VIEW_FLAT) {
            return;
        }

        $this->buildCommentReplyToCssClasses($sender);
    }

    /**
     * Add the option to "Reply" the comment.
     *
     * @param $sender
     * @param $args
     */
    public function discussionController_commentOptions_handler($sender, $args) {
        ReplyToPlugin::log('discussionController_CommentOptions_handler', ['CommentID' =>$args['Comment']->CommentID]);
        if (!Gdn::Session()->isValid()) {
            return;
        }
        $discussion = $sender->data('Discussion');
        $isClosed = ((int)$discussion->Closed) == 1;
        if ($isClosed) {
            return;
        }

        //Check permission
        if (isset($discussion->PermissionCategoryID)) {
            $CategoryID = $discussion->CategoryPermissionID;
        } else {
            $CategoryID = $discussion->CategoryID;
        }

        // Can the user comment on this category, and is the discussion open for comments?
        if (!Gdn::Session()->CheckPermission('Vanilla.Comments.Add', TRUE, 'Category', $CategoryID)) {
            return;
        }

        $options = &$args['CommentOptions'];
        $comment = &$args['Comment'];
        $options['ReplyToComment'] = [
            'Label' => t('Reply'),
            'Url' => '/?ParentCommentID='.$comment->CommentID,
            'Class' => 'ReplyComment'
        ];

        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW, self::VIEW_FLAT);
        foreach ($options as $key => $value) {
            $currentUrl =  $options[$key]['Url'];
            if (strpos($currentUrl, '?') !== false ) {
                if (strpos($currentUrl, 'Target') !== false) {
                    $options[$key]['Url'] = $currentUrl.urlencode('?view='.$viewMode);
                } else {
                    $options[$key]['Url'] = $currentUrl. '&view=' . $viewMode;
                }
            } else {
                $options[$key]['Url'] = $currentUrl.'?view='.$viewMode;
            }
        }
    }

    /**
     * Insert the indentation classes into the comment.
     * @param $sender
     * @param $args
     */
    public function base_beforeCommentDisplay_handler($sender, $args) {
        ReplyToPlugin::log('base_beforeCommentDisplay_handler', []);

        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW, self::VIEW_FLAT);
        if($viewMode == self::VIEW_FLAT) {
           return;
        }
        if($sender->deliveryType() != DELIVERY_TYPE_ALL) {
            ReplyToPlugin::log('base_beforeCommentDisplay_handler', ['']);
            $this->buildCommentReplyToCssClasses($sender);
        }
        $comment = &$args['Comment'];
        $cssClass = &$args['CssClass'];
        $displayBody = &$args['DisplayBody'];
        $displayBody = $viewMode == self::VIEW_FLAT || $viewMode == self::VIEW_THREADED;
        $cssClass .= (!empty($comment->ReplyToClass)? ' ' . $comment->ReplyToClass : '');
    }

    private function buildCommentReplyToCssClasses(&$sender){
        // Get a list of all comment IDs in this set, i.e. displayed on this page.
        $CommentIDs = array();
        $MaxTreeRight = 1;
        $DepthCounts = array();

        foreach($sender->data('Comments') as $Comment) {
            $CommentIDs[$Comment->CommentID] = $Comment->CommentID;
            if ($Comment->TreeRight > $MaxTreeRight) {
                $MaxTreeRight = $Comment->TreeRight + 1;
            }
        }

        // Find all comments that have parents on a previous page.
        $NoParents = array();
        foreach($sender->data('Comments') as $Comment) {
            if (!empty($Comment->ParentCommentID) && empty($CommentIDs[$Comment->ParentCommentID])) {
                $NoParents[] = $Comment->CommentID;
            }
        }

        if (!empty($NoParents)) {
            $DepthCounts = $this->replyToModel->CountAncestors($NoParents);
        }

        // Loop for each comment and build a depth and give them some categories.
        $depthstack = array();

        foreach($sender->Data['Comments'] as $Comment) {
            // If we hit a comment without a parent, then treat it as level 0.
            if (empty($Comment->ParentCommentID)) {
                $depthstack = array();
            }

            // If this comment has a parent that is not on this page, then provide a link
            // back to the parent.
            if (!empty($Comment->ParentCommentID) && empty($CommentIDs[$Comment->ParentCommentID])) {
                $Comment->ReplyToParentURL = Gdn::Request()->Url(
                    'discussion/comment/' . $Comment->ParentCommentID . '/#Comment_' . $Comment->ParentCommentID,
                    TRUE
                );

                // Set the depth as one more than its number of ancestors.
                if (isset($DepthCounts[$Comment->CommentID])) {
                    // Fill out the depth array just to fool the algorithm.
                    // We probably could do it more efficiently with an offset, but then have two
                    // variables to account for the depth.
                    $depthstack = array_pad(array(), $DepthCounts[$Comment->CommentID], $MaxTreeRight);
                }
            }

            // Calculate the depth of the comment (within the context of the selected comments, i.e. not
            // in absolute terms.
            while (!empty($depthstack) && end($depthstack) < $Comment->TreeRight) {
                array_pop($depthstack);
            }

            $depth = count($depthstack);
            $depthstack[] = $Comment->TreeRight;

            $Comment->ReplyToDepth = $depth;

            // TODO: if a tree is cut short or starts half-way through, then links to the rest
            // of the replies would be useful, e.g. "replies continue..." and "this is a reply to...".
            // Links to individual comments are possible, and would be ideal.

            // Set the class of the comment according to depth.
            $Comment->ReplyToClass = $this->replyToModel->depthClasses($depth);
        }
    }

    public static function log($message, $data) {
        if (c('Debug')) {
            Logger::event(
                'replyto_plugin',
                Logger::INFO,
                $message,
                $data
            );
        }
    }

}