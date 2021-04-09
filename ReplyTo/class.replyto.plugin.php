<?php
use Garden\Schema\Schema;
use Garden\Web\Data;
use Garden\Web\Exception\ClientException;
use Garden\Web\Exception\NotFoundException;
use Vanilla\ApiUtils;

class ReplyToPlugin extends Gdn_Plugin {

    const QUERY_PARAMETER_VIEW='view';
    const VIEW_FLAT = 'flat';
    const VIEW_THREADED = 'threaded';
    const VIEW_MODE = 'ReplyTo.ViewMode';

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

    /**
     * Set a view mode for Discussion Controller
     * View Mode is calculated from request url.
     * Flat mode  is used  - '/discussion/{DiscussionID}/p{Page}
     * Threaded mode is used by default
     *
     * @param $sender
     * @param $args
     */
    public function discussionController_initialize_handler($sender, $args) {
        $viewMode = self::getViewMode();
        $sender->setData(self::VIEW_MODE, $viewMode);

    }

    /**
     * Set a view mode for Post Controller
     * Replying to a comment and leaving a comment are processed by Post Controller.
     * (the url 'post/comment/, 'post' method).
     * Use HTTP_REFERER to get the current view mode
     * @param $sender
     * @param $args
     */
    public function postController_initialize_handler($sender, $args) {
        if(isset($_SERVER['HTTP_REFERER'])) {
            $url = $_SERVER['HTTP_REFERER'];
        }
        parse_str( parse_url( $url, PHP_URL_QUERY), $array );
        $viewMode = $array[self::QUERY_PARAMETER_VIEW];
        if(!$viewMode) {
            $viewMode = self::isPagingUrl($url)? self::VIEW_FLAT: self::VIEW_THREADED;
        }
        $sender->setData(self::VIEW_MODE, $viewMode);
    }

    public function discussionController_render_before(&$sender) {
        $this->prepareController($sender);
    }

    /**
     * After deleting a comment in a threaded view, the comment tree should be re-rendered
     * because tree left/right might be changed if a parent comment has been deleted.
     * deliveryType is VIEW in a threaded view
     * deliveryType is BOOL in a flat view. Don't re-render a view. Deleted comment
     * is hidden on the client.
     *
     * @param $sender
     * @param $args
     */
    public function discussionController_AfterCommentDeleted_handler($sender, $args) {
        $viewMode = $sender->data('ReplyTo.ViewMode');
        if($sender->deliveryMethod() == DELIVERY_METHOD_JSON) {
            $discussionID = $args['DiscussionID'];
            $sender->json(self::VIEW_MODE, $viewMode);
            if ($viewMode ==  self::VIEW_THREADED) {
                // Show all comments
                $commentModel = new CommentModel();
                $CountComments = $commentModel->getCountByDiscussion($discussionID);
                $sender->setData('Comments', $commentModel->getByDiscussion($discussionID, $CountComments, 0));
                $sender->ClassName = 'DiscussionController';
                $sender->ControllerName = 'discussion';
                $sender->View = 'comments';
            }
        }
    }

    public function postController_render_before($sender) {
        $this->prepareController($sender);
    }

    /**
     * The 'beforeCommentRender' are fired by DiscussionController and PostController.
     * Re-render a comment tree if new comment is added in threaded view.
     *
     * @param $sender
     * @param $args
     */
    public function base_beforeCommentRender_handler($sender, $args) {
        // Editing existing comment or new comment added
        if ($sender->deliveryType() != DELIVERY_TYPE_DATA) {
            $sender->json('ReplyTo.ViewMode', $sender->data(self::VIEW_MODE));
            $isNewComment =  $sender->data('NewComments');
            if($isNewComment) {
                $discussionID = val('DiscussionID', $args['Discussion']);
                $commentModel = new CommentModel();
                $countComments = $commentModel->getCountByDiscussion($discussionID);
                // FIX: https://github.com/topcoder-platform/forums/issues/511
                // Render a full comment tree in threaded mode
                if($sender->data(self::VIEW_MODE) == self::VIEW_THREADED) {
                    // Show all comments
                    $sender->setData('Comments', $commentModel->getByDiscussion($discussionID, $countComments, 0));
                }
            }
        }
    }

    /**
     * Render View options for a discussion
     * @param $sender
     * @param $args
     */
    public function discussionController_InlineDiscussionOptionsLeft_handler($sender, $args){
        $discussion = $sender->data('Discussion');
        if (!$discussion) {
            return;
        }

        if (isset($args['Comment'])) {
            return;
        }

        $discussionUrl = discussionUrl($discussion, '', '/');
        $viewMode = $sender->data(self::VIEW_MODE);

        echo '<span class="ReplyViewOptions">';
        echo '<span class="MLabel">View:&nbsp</span>';
        echo anchor('Threaded', $discussionUrl.'?'.self::QUERY_PARAMETER_VIEW.'='.self::VIEW_THREADED, $viewMode == self::VIEW_THREADED?'ReplyViewOptionLink Active':'ReplyViewOptionLink').'&nbsp;&nbsp;|&nbsp;&nbsp;';
        echo anchor('Flat', $discussionUrl.'?'.self::QUERY_PARAMETER_VIEW.'='.self::VIEW_FLAT, $viewMode == self::VIEW_FLAT?'ReplyViewOptionLink Active':'ReplyViewOptionLink');
        echo '</span>';
    }

    /**
     * Set the tree order of all comments in the model as soon as it is instantiated.
     * It is not clear if there are other plugins that may also wish to change the ordering.
     * @param $sender
     */
    public function commentModel_afterConstruct_handler(&$sender) {
        $viewMode = self::getViewMode();

        if($viewMode == self::VIEW_THREADED) {
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
     * Set offset and limit depends on view mode.
     * In the threaded mode, all comments are displayed.
     * In the flat mode, comments are displayed with pagination.
     * The hook is used when rendering a discussion page with comments
     * @param $sender
     * @param $args
     */
    public function discussionController_BeforeCalculatingOffsetLimit_handler($sender, $args) {
         $viewMode = $sender->data(self::VIEW_MODE);
        //  $offsetProvided = $args['OffsetProvided'];
        $discussion = $args['Discussion'];
        $offset = & $args['Offset'];
        $limit = & $args['Limit'];
        $enableAutoOffset = & $args['EnableAutoOffset'];

        if(!$discussion) {
            return;
        }

        if($viewMode === self::VIEW_FLAT) {
            $enableAutoOffset = false;
        } else {
            // Show all comment on one offset for Tree/Threaded View
            // Don't set MAX Int
            $CountComments = val('CountComments', $discussion);
            $offset = 0;
            $limit = $CountComments > 0? $CountComments: c('Vanilla.Comments.PerPage', 30);;
            $enableAutoOffset = false;
        }
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

        $viewMode = $sender->data(self::VIEW_MODE);
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
    public function base_commentOptions_handler($sender, $args) {
        ReplyToPlugin::log('base_CommentOptions_handler', ['CommentID' =>$args['Comment']->CommentID]);
        if (!Gdn::Session()->isValid()) {
            return;
        }
        $discussion = $sender->data('Discussion');

        //Check permission
        $CategoryID = val('PermissionCategoryID', $discussion)? val('PermissionCategoryID', $discussion):val('CategoryID', $discussion);
        $userCanClose = CategoryModel::checkPermission($CategoryID, 'Vanilla.Discussions.Close');
        $userCanComment = CategoryModel::checkPermission($CategoryID, 'Vanilla.Comments.Add');

        $canAddComment = ($discussion->Closed == '1' && $userCanClose) || ($discussion->Closed == '0' && $userCanComment);
        if (!$canAddComment) {
            return;
        }
        // Can the user comment on this category, and is the discussion open for comments?
       // if (!Gdn::Session()->CheckPermission('Vanilla.Comments.Add', TRUE, 'Category', $CategoryID)) {
       //     return;
       // }

        $options = &$args['CommentOptions'];
        $comment = $args['Comment'];
        $options['ReplyToComment'] = [
            'Label' => t('Reply'),
            'Url' => '/?ParentCommentID='.$comment->CommentID,
            'Class' => 'ReplyComment'
        ];

        $viewMode = $sender->data(self::VIEW_MODE);
        $deliveryType = $viewMode == self::VIEW_THREADED? DELIVERY_TYPE_VIEW : DELIVERY_TYPE_BOOL;
        foreach ($options as $key => $value) {
            $options[$key]['Url']  = strpos($options[$key]['Url'], '?') !== false ? $options[$key]['Url']: $options[$key]['Url'].'?';
            $options[$key]['Url'] .= '&view=' . $viewMode;
            if($key == 'DeleteComment') {
                $options[$key]['Url'] .='&deliveryType='.$deliveryType;
            }
        }

    }

    /**
     * Add 'Reply' option to discussion.
     *
     * @param Gdn_Controller $sender
     * @param array $args
     */
    public function base_inlineDiscussionOptions_handler($sender, $args) {
        $discussion = $args['Discussion'];
        if (!$discussion) {
            return;
        }

        if (!Gdn::session()->UserID) {
            return;
        }

        //Check permission
        $CategoryID = val('PermissionCategoryID', $discussion)? val('PermissionCategoryID', $discussion):val('CategoryID', $discussion);
        $userCanClose = CategoryModel::checkPermission($CategoryID, 'Vanilla.Discussions.Close');
        $userCanComment = CategoryModel::checkPermission($CategoryID, 'Vanilla.Comments.Add');

        // See  the 'writeCommentForm' method vanilla/applications/vanilla/views/discussion/helper_functions.php
        $canAddComment = ($discussion->Closed == '1' && $userCanClose) || ($discussion->Closed == '0' && $userCanComment);
        if (!$canAddComment) {
            return;
        }

        // DropdownModule options
        $options = & $args['DiscussionOptions'];
        $options->addLink('Reply', url("/", true), 'reply', 'ReplyComment');
    }

    /**
     * Insert the indentation classes into the comment.
     * All rendering options should be set before displaying comments
     * @param $sender
     * @param $args
     */
    public function base_beforeCommentDisplay_handler($sender, $args) {
        if($sender->deliveryType() != DELIVERY_TYPE_ALL) { // Editing a comment is processed by PostController
            // Ajax request to post new comments or update comments
            if(isset($_SERVER['HTTP_REFERER'])) {
                $previous = $_SERVER['HTTP_REFERER'];
                $query = parse_url($previous, PHP_URL_QUERY);
                parse_str($query, $params);
                $viewMode = $params['view'];
                if(!$viewMode) {
                    $viewMode = self::isPagingUrl($previous) ? self::VIEW_FLAT : self::VIEW_THREADED;
                }
                $sender->setData(self::VIEW_MODE, $viewMode);
                if($viewMode == self::VIEW_THREADED) {
                    $this->buildCommentReplyToCssClasses($sender);
                }
            }
        } else {
            $viewMode = $sender->data(self::VIEW_MODE);
            if($viewMode == self::VIEW_THREADED) {
                $this->buildCommentReplyToCssClasses($sender);
            }
        }
        $comment = &$args['Comment'];
        $cssClass = &$args['CssClass'];
        // $displayBody = &$args['DisplayBody'];
        // $displayBody = $viewMode == self::VIEW_FLAT || $viewMode == self::VIEW_THREADED;
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

    private static function isPagingUrl($url) {
        return preg_match('/\/p\d+$/', $url);
    }

    private static function getViewMode(){
        $viewMode = getIncomingValue(self::QUERY_PARAMETER_VIEW);
        if(!$viewMode) {
            $viewMode = self::isPagingUrl(Gdn::request()->path())? self::VIEW_FLAT: self::VIEW_THREADED;
        }

        return $viewMode;
    }

    public static function log($message, $data) {
        if (c('Debug')) {
            Logger::event(
                'replyto_plugin',
                Logger::DEBUG,
                $message,
                $data
            );
        }
    }

}